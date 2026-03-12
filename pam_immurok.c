/*
 * pam_immurok.c - PAM module for immurok fingerprint authentication (Linux)
 *
 * Communicates with immurok-daemon via Unix socket at ~/.immurok/pam.sock.
 * The socket path is resolved from the authenticating user's home directory.
 * Protocol: "AUTH:username:service" -> "OK", "DENY", or "TIMEOUT"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <syslog.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define SOCKET_NAME ".immurok/pam.sock"
#define DEFAULT_TIMEOUT_SEC 40
#define BUFFER_SIZE 256

/* Parse timeout=N from PAM module arguments */
static int parse_timeout(int argc, const char **argv) {
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "timeout=", 8) == 0) {
            int val = atoi(argv[i] + 8);
            if (val > 0) return val;
        }
    }
    return DEFAULT_TIMEOUT_SEC;
}

/* Send authentication request to immurok-daemon and wait for response */
static int authenticate_via_socket(pam_handle_t *pamh, const char *user,
                                   const char *service, int timeout_sec) {
    int sock;
    struct sockaddr_un addr;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    char socket_path[256];
    ssize_t n;
    struct timeval tv;
    struct passwd *pw;

    /* Resolve the authenticating user's home directory */
    pw = getpwnam(user);
    if (pw == NULL || pw->pw_dir == NULL) {
        pam_syslog(pamh, LOG_ERR, "Cannot resolve home for user: %s", user);
        return PAM_AUTH_ERR;
    }
    snprintf(socket_path, sizeof(socket_path), "%s/%s", pw->pw_dir, SOCKET_NAME);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return PAM_AUTH_ERR;

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to connect to %s: %s",
                   socket_path, strerror(errno));
        close(sock);
        return PAM_AUTH_ERR;
    }

    snprintf(request, sizeof(request), "AUTH:%s:%s", user, service);
    if (send(sock, request, strlen(request), 0) < 0) {
        close(sock);
        return PAM_AUTH_ERR;
    }

    memset(response, 0, sizeof(response));
    n = recv(sock, response, sizeof(response) - 1, 0);
    close(sock);

    if (n > 0 && strncmp(response, "OK", 2) == 0) {
        pam_syslog(pamh, LOG_INFO, "Approved for user %s", user);
        return PAM_SUCCESS;
    }

    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *user = NULL;
    const char *service = NULL;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL)
        return PAM_AUTH_ERR;

    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS || service == NULL)
        service = "unknown";

    int timeout_sec = parse_timeout(argc, argv);
    pam_syslog(pamh, LOG_INFO, "Auth request: user=%s service=%s timeout=%d",
               user, service, timeout_sec);

    pam_info(pamh, "Please verify your fingerprint in 30s");

    return authenticate_via_socket(pamh, user, service, timeout_sec);
}

/* Required PAM stubs */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
