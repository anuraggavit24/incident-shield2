"""Print fresh keys for sealed risk decisions. Put them in .env (and Render), never in git or chat.

Losing RISK_ENC_KEY_* makes existing sealed decisions unreadable. To rotate: add a new pair with a new id
(K2), point RISK_ACTIVE_KEY_ID at it, and keep the old pair so old records still open.
"""

import secrets

if __name__ == "__main__":
    print(f"RISK_ENC_KEY_K1={secrets.token_hex(32)}")
    print(f"RISK_SIGN_KEY_K1={secrets.token_hex(32)}")
    print("RISK_ACTIVE_KEY_ID=k1")
