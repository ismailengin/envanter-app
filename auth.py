import ldap
import ldap.modlist
from config import (
    LDAP_ENABLED, LDAP_SERVER, LDAP_BASE_DN, LDAP_BIND_DN, LDAP_BIND_PASSWORD,
    LDAP_USER_SEARCH_BASE, LDAP_USER_SEARCH_FILTER, LDAP_USER_SEARCH_ATTRIBUTE,
    LDAP_TLS_CACERTFILE, LDAP_TLS_REQCERT, users, user_roles
)

def is_valid_credentials(username, password):
    # Check if the provided username and password are valid
    return users.get(username) == password

def authenticate_ldap_user(username, password):
    if not LDAP_ENABLED:
        return False

    # Set LDAP options for TLS/SSL
    if LDAP_TLS_CACERTFILE:
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, LDAP_TLS_CACERTFILE)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, getattr(ldap.constants, f"LDAP_OPT_X_TLS_REQUIRE_CERT_{LDAP_TLS_REQCERT.upper()}"))

    try:
        l = ldap.initialize(LDAP_SERVER)
        l.set_option(ldap.OPT_REFERRALS, 0)
        l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

        # First, bind with a service account (if configured) to search for the user DN
        if LDAP_BIND_DN and LDAP_BIND_PASSWORD:
            l.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWORD)
        else:
            l.simple_bind_s()

        # Search for the user DN
        search_filter = LDAP_USER_SEARCH_FILTER.format(username)
        result = l.search_s(LDAP_USER_SEARCH_BASE, ldap.SCOPE_SUBTREE, search_filter, [LDAP_USER_SEARCH_ATTRIBUTE])

        if not result:
            print(f"LDAP: User {username} not found.")
            return False

        user_dn = result[0][0] # Get the user's DN
        if not user_dn:
            print(f"LDAP: Could not retrieve DN for user {username}.")
            return False

        # Second, try to bind as the user with their provided password
        l.simple_bind_s(user_dn, password)
        print(f"LDAP: User {username} authenticated successfully.")
        return True
    except ldap.INVALID_CREDENTIALS:
        print(f"LDAP: Invalid credentials for user {username}.")
        return False
    except ldap.SERVER_DOWN:
        print(f"LDAP: Server {LDAP_SERVER} is down or unreachable.")
        return False
    except ldap.LDAPError as e:
        print(f"LDAP: An LDAP error occurred for user {username}: {e}")
        return False
    except Exception as e:
        print(f"LDAP: An unexpected error occurred during LDAP authentication for user {username}: {e}")
        return False

def get_user_allowed_endpoints(username):
    # Return allowed endpoints for the user
    return user_roles.get(username, user_roles['default'])
