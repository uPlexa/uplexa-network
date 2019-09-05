#include <udap/link.h>

bool
udap_link_initialized(struct udap_link* link)
{
  return link && link->impl && link->name && link->get_our_address
      && link->configure && link->start_link && link->stop_link
      && link->iter_sessions && link->try_establish && link->sendto
      && link->has_session_to && link->mark_session_active && link->free_impl;
}

bool
udap_link_session_initialized(struct udap_link_session* s)
{
  return s && s->impl && s->sendto && s->timeout && s->close
      && s->get_remote_router && s->established && s->get_parent;
}
