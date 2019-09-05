#ifndef UDAP_VERSION_H
#define UDAP_VERSION_H

#ifndef UDAP_VERSION_MAJ
#define UDAP_VERSION_MAJ "0"
#endif

#ifndef UDAP_VERSION_MIN
#define UDAP_VERSION_MIN "0"
#endif

#ifndef UDAP_VERSION_PATCH
#define UDAP_VERSION_PATCH "0"
#endif

#ifndef UDAP_VERSION_NUM
#ifdef GIT_REV
#define UDAP_VERSION_NUM                                             \
  "-" UDAP_VERSION_MAJ "." UDAP_VERSION_MIN "." UDAP_VERSION_PATCH \
  "-" GIT_REV
#else
#define UDAP_VERSION_NUM \
  "-" UDAP_VERSION_MAJ "." UDAP_VERSION_MIN "." UDAP_VERSION_PATCH
#endif
#endif
#define UDAP_VERSION "udapd" UDAP_VERSION_NUM

#ifndef UDAP_RELEASE_MOTTO
#define UDAP_RELEASE_MOTTO "(dev build)"
#endif
#endif
