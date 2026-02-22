#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <shadow.h>
#include <crypt.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <security/pam_ext.h>
#include <time.h>

#define ENABLE_TIMESTAMPS 0
#define ENABLE_IP_LOGGING 1

#define LOG_MESSAGE(level, pamh, message, ...) \
\tpam_syslog(pamh, level, "%s" message "%s", timeString, ##__VA_ARGS__, ipString)

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
  /* printf ("setcred  %d %d\n", argc, flags); */
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	const char* pUsername;
	char wUsername[128];
	char* wPassword;
	int pwTest = -1;
	char c = 0; int i = 0;

	char timeString[80] = "";
	char ipString[64] = "";

#if ENABLE_TIMESTAMPS
	time_t now = time(NULL);
	struct tm *timeinfo = localtime(&now);
	strftime(timeString, sizeof(timeString), "[%Y-%m-%d %H:%M:%S] ", timeinfo);
#endif

#if ENABLE_IP_LOGGING
	const char *ipAddr = pam_getenv(pamh, "REMOTE_ADDR");
	if (!ipAddr) {
	  ipAddr = "unknown";
	}
	snprintf(ipString, sizeof(ipString), " (IP=%s)", ipAddr);
#endif

	if (PAM_SUCCESS != pam_get_user(pamh, &pUsername, NULL)) {
	  return PAM_INCOMPLETE;
	}

	if (argc == 1) {
	  /* first argument is a username, we use this as default */
	  sscanf(argv[0], "%s", wUsername);
	  printf("Withness login for %s\n", wUsername);
	} else {
	  printf("Whithness login: ");
	  scanf("%s", wUsername);
	}

	if (wUsername == NULL || wUsername[0] == '-' || wUsername[0] == '+') {
	  /* unix does not allow this as well  */
	  LOG_MESSAGE(LOG_ERR, pamh, "bad username [%s]", wUsername);
	  return PAM_USER_UNKNOWN;
	}
	wPassword = getpass("Whitness password: ");

	if (0 == strcmp(wUsername, pUsername)) {
	  printf("Whitness can not be the same user!\n");
	  LOG_MESSAGE(LOG_CRIT, pamh, "auth whitness and login are identical [%s - %s]", pUsername, wUsername);
	  /* return PAM_AUTH_ERR; */
	}

	struct passwd* passwdEntry = getpwnam(wUsername);
	if (!passwdEntry) {
	  printf("User '%s' doesn't exist\n", wUsername);
	  LOG_MESSAGE(LOG_CRIT, pamh, "auth could not identify username %s", wUsername);
	  return PAM_USER_UNKNOWN;
	}

	if (0 != strcmp(passwdEntry->pw_passwd, "x")) {
	  /* x -> we try with shadow file  */
	  pwTest = strcmp(passwdEntry->pw_passwd, crypt(wPassword, passwdEntry->pw_passwd));
	} else {
	  struct spwd* shadowEntry = getspnam(wUsername);
	  if (!shadowEntry) {
		LOG_MESSAGE(LOG_CRIT, pamh, "auth can not read shadow entry for %s", wUsername);
		return PAM_AUTH_ERR;
	  }

	  pwTest = strcmp(shadowEntry->sp_pwdp, crypt(wPassword, shadowEntry->sp_pwdp));
	}   

	if (pwTest == 0) {
	  return PAM_SUCCESS;
	}

	return PAM_AUTH_ERR;
}