"""
Verification for the eighth-round review fix.

Run from the repo root:  python3 tests/test_round8.py

Covers:
  F1  checkout.session.completed only grants paid access when the session
      actually settled. Stripe fires this event for mode="subscription" even
      when the first invoice fails or SCA is abandoned — the session arrives
      with payment_status "unpaid" and the subscription is left `incomplete`.
      An unpaid session must leave is_active alone and send no welcome email,
      while "paid" and (trials) "no_payment_required" still activate.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)
# A configured Stripe price turns the paywall on. Nothing here talks to Stripe.
os.environ["STRIPE_PRICE_ID"] = "price_test_round8"
os.environ["STRIPE_SECRET_KEY"] = "sk_test_dummy"

import stripe  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app.main as main  # noqa: E402
from app.models import Base, User, get_session  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# ------------------------------------------------------------------ fixtures

_tmpfiles = []


def fresh_db():
    """A throwaway database with one unpaid account."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = get_session(engine)
    user = User(email=f"r8-{len(_tmpfiles)}@test.local", password_hash="x", is_active=False)
    db.add(user)
    db.commit()
    user_id = user.id
    db.close()
    return engine, user_id


def _webhook_event(event):
    """Make construct_event return `event` regardless of the signature."""
    def constructed(payload, sig_header, secret, *a, **k):
        return event
    return staticmethod(constructed)


# ---------------------------------------- (F1) unpaid checkout grants nothing

def test_unpaid_checkout_session_does_not_activate():
    print("\n[F1] An unsettled checkout.session.completed grants no paid access")
    engine, user_id = fresh_db()

    emails = {"n": 0}

    async def fake_welcome(to_email):
        emails["n"] += 1
        return True

    real = (main.engine, main.STRIPE_WEBHOOK_SECRET, main.send_welcome_email,
            stripe.Webhook.construct_event)
    main.engine = engine
    main.STRIPE_WEBHOOK_SECRET = "whsec_test_round8"
    main.send_welcome_email = fake_welcome
    try:
        client = TestClient(main.app)
        client.__enter__()

        def post_session(payment_status, customer="cus_r8", subscription="sub_r8",
                         status="open"):
            obj = {
                "metadata": {"user_id": str(user_id)},
                "customer": customer, "subscription": subscription,
                "status": status,
            }
            if payment_status is not None:
                obj["payment_status"] = payment_status
            stripe.Webhook.construct_event = _webhook_event({
                "type": "checkout.session.completed",
                "data": {"object": obj},
            })
            return client.post("/stripe-webhook", content=b"{}",
                               headers={"stripe-signature": "t=1,v1=valid"})

        def load():
            db = get_session(engine)
            try:
                return db.query(User).filter(User.id == user_id).one()
            finally:
                db.close()

        def deactivate():
            db = get_session(engine)
            u = db.query(User).filter(User.id == user_id).one()
            u.is_active = False
            db.commit()
            db.close()

        # (a) The live-verified exploit: SCA abandoned, session left unpaid.
        r = post_session("unpaid")
        check("unpaid checkout.session.completed -> 200", r.status_code == 200,
              str(r.status_code))
        check("an unpaid session does NOT activate the account",
              load().is_active is False)
        check("an unpaid session sends no welcome email", emails["n"] == 0,
              str(emails["n"]))

        # It stays closed however many times it is replayed.
        for _ in range(3):
            post_session("unpaid")
        check("replaying the unpaid session still grants nothing",
              load().is_active is False)

        # (b) Anything other than a settled status is refused too — including a
        # session with the field missing entirely.
        for payment_status in ("no_payment_required_", "", "open", None):
            deactivate()
            r = post_session(payment_status)
            check(f"payment_status={payment_status!r} -> 200", r.status_code == 200,
                  str(r.status_code))
            check(f"payment_status={payment_status!r} does not activate",
                  load().is_active is False)

        # (c) The unpaid session still linked the customer id, so a subscription
        # that settles later can be matched back to this account.
        check("an unpaid session links the Stripe customer id",
              load().stripe_customer_id == "cus_r8", str(load().stripe_customer_id))

        stripe.Webhook.construct_event = _webhook_event({
            "type": "customer.subscription.updated",
            "data": {"object": {"id": "sub_r8", "customer": "cus_r8",
                                "status": "active"}},
        })
        r = client.post("/stripe-webhook", content=b"{}",
                        headers={"stripe-signature": "t=1,v1=valid"})
        check("a subscription that settles later -> 200", r.status_code == 200,
              str(r.status_code))
        check("a subscription that settles later does entitle the account",
              load().is_active is True)

        # (d) A genuinely paid session activates, and so does a trial.
        deactivate()
        r = post_session("paid", subscription="sub_paid", status="complete")
        check("payment_status=paid -> 200", r.status_code == 200, str(r.status_code))
        check("payment_status=paid activates the account", load().is_active is True)
        check("payment_status=paid records the subscription id",
              load().stripe_subscription_id == "sub_paid",
              str(load().stripe_subscription_id))
        check("payment_status=paid sends the welcome email", emails["n"] == 1,
              str(emails["n"]))

        deactivate()
        r = post_session("no_payment_required", subscription="sub_trial",
                         status="complete")
        check("payment_status=no_payment_required -> 200", r.status_code == 200,
              str(r.status_code))
        check("a trial (no_payment_required) activates the account",
              load().is_active is True)
        check("a trial sends the welcome email", emails["n"] == 2, str(emails["n"]))

        # (e) An unpaid session cannot repoint a customer id we already trust —
        # that would orphan the account from its paying subscription's events.
        deactivate()
        post_session("unpaid", customer="cus_attacker", subscription="sub_attacker")
        user = load()
        check("an unpaid session cannot overwrite a known customer id",
              user.stripe_customer_id == "cus_r8", str(user.stripe_customer_id))
        check("an unpaid session cannot overwrite a known subscription id",
              user.stripe_subscription_id == "sub_trial",
              str(user.stripe_subscription_id))
        check("an unpaid session still does not activate", user.is_active is False)

        client.__exit__(None, None, None)
    finally:
        (main.engine, main.STRIPE_WEBHOOK_SECRET, main.send_welcome_email,
         stripe.Webhook.construct_event) = real


if __name__ == "__main__":
    try:
        test_unpaid_checkout_session_does_not_activate()
    finally:
        for path in _tmpfiles:
            try:
                os.unlink(path)
            except OSError:
                pass

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED: " + ", ".join(FAIL))
    sys.exit(1 if FAIL else 0)
