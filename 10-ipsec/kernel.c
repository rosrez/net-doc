/* programs/pluto/kernel_netlink.c */

const struct kernel_ops netkey_kernel_ops = {
        .kern_name = "netkey",
        .type = USE_NETKEY,
        .inbound_eroute =  TRUE,
        .policy_lifetime = TRUE,
        .async_fdp = &netlink_bcast_fd,
        .replay_window = IPSEC_SA_DEFAULT_REPLAY_WINDOW,

        .init = init_netlink,
        .pfkey_register = linux_pfkey_register,
        .pfkey_register_response = pfkey_register_response,
        .process_msg = netlink_process_msg,
        .raw_eroute = netlink_raw_eroute,
        .add_sa = netlink_add_sa,
        .del_sa = netlink_del_sa,
        .get_sa = netlink_get_sa,
        .process_queue = NULL,
        .grp_sa = NULL,
        .get_spi = netlink_get_spi,
        .exceptsocket = NULL,
        .docommand = netkey_do_command,
        .process_ifaces = netlink_process_raw_ifaces,
        .shunt_eroute = netlink_shunt_eroute,
        .sag_eroute = netlink_sag_eroute,
        .eroute_idle = netlink_eroute_idle,
        .set_debug = NULL,      /* pfkey_set_debug, */
        /*
         * We should implement netlink_remove_orphaned_holds
         * if netlink  specific changes are needed.
         */
        .remove_orphaned_holds = NULL, /* only used for klips /proc scanner */
        .overlap_supported = FALSE,
        .sha2_truncbug_support = TRUE,
};

/*
 * install or remove eroute for SA Group
 *
 * (identical to KLIPS version, but refactoring isn't waranteed yet
 */
static bool netlink_sag_eroute(const struct state *st, const struct spd_route *sr,
                        unsigned op, const char *opname)
{
        struct connection *c = st->st_connection;
        unsigned int inner_proto;
        enum eroute_type inner_esatype;
        ipsec_spi_t inner_spi;
        struct pfkey_proto_info proto_info[4];
        int i;
        bool tunnel;

        /*
         * figure out the SPI and protocol (in two forms)
         * for the innermost transformation.
         */
        i = elemsof(proto_info) - 1;
        proto_info[i].proto = 0;
        tunnel = FALSE;

        inner_proto = 0;
        inner_esatype = ET_UNSPEC;
        inner_spi = 0;

        /* ... */

        if (st->st_esp.present) {
                inner_spi = st->st_esp.attrs.spi;
                inner_proto = SA_ESP;
                inner_esatype = ET_ESP;

                i--;
                proto_info[i].proto = IPPROTO_ESP;
                proto_info[i].encapsulation = st->st_esp.attrs.encapsulation;
                tunnel |= proto_info[i].encapsulation ==
                        ENCAPSULATION_MODE_TUNNEL;
                proto_info[i].reqid = reqid_esp(sr->reqid);
        }

        if (st->st_ipcomp.present) {
                inner_spi = st->st_ipcomp.attrs.spi;
                inner_proto = SA_COMP;
                inner_esatype = ET_IPCOMP;                      /* OR: HERE - choose ipcomp; value == 108 */

                i--;
                proto_info[i].proto = IPPROTO_COMP;
                proto_info[i].encapsulation =
                        st->st_ipcomp.attrs.encapsulation;
                tunnel |= proto_info[i].encapsulation ==
                        ENCAPSULATION_MODE_TUNNEL;
                proto_info[i].reqid = reqid_ipcomp(sr->reqid);
        }

        /* ... */

        if (tunnel) {
                int j;

                inner_spi = st->st_tunnel_out_spi;
                inner_proto = SA_IPIP;
                inner_esatype = ET_IPIP;

                proto_info[i].encapsulation = ENCAPSULATION_MODE_TUNNEL;
                for (j = i + 1; proto_info[j].proto; j++)
                        proto_info[j].encapsulation =
                                ENCAPSULATION_MODE_TRANSPORT;
        }

        return eroute_connection(sr, inner_spi, inner_spi, inner_proto,         /* OR: HERE */
                                inner_esatype, proto_info + i,
                                c->sa_priority, &c->sa_marks, op, opname        /* OR: ERO_ADD, "add" */
#ifdef HAVE_LABELED_IPSEC
                                , st->st_connection->policy_label
#endif
                );
}

/* ------------------------------------------------------ */

/* programs/pluto/kernel.c */

bool eroute_connection(const struct spd_route *sr,
                       ipsec_spi_t cur_spi,
                       ipsec_spi_t new_spi,
                       int sa_proto, enum eroute_type esatype,
                       const struct pfkey_proto_info *proto_info,
                       uint32_t sa_priority,
                       const struct sa_marks *sa_marks,
                       unsigned int op, const char *opname
#ifdef HAVE_LABELED_IPSEC
                       , const char *policy_label
#endif
                       )
{
        const ip_address *peer = &sr->that.host_addr;           /* OR: HERE; peer derived from sr->that */
        char buf2[256];

        snprintf(buf2, sizeof(buf2),
                 "eroute_connection %s", opname);               /* OR: "eroute_connection add" */

        if (sa_proto == SA_INT)
                peer = aftoinfo(addrtypeof(peer))->any;

        return raw_eroute(&sr->this.host_addr, &sr->this.client,
                          peer, &sr->that.client,               /* sr->that.client -- determines peer client, i.e subnet */
                          cur_spi,
                          new_spi,
                          sa_proto,
                          sr->this.protocol,
                          esatype,
                          proto_info,
                          deltatime(0),
                          sa_priority, sa_marks, op, buf2       /* pass "eroute_connection add" */
#ifdef HAVE_LABELED_IPSEC
                          , policy_label
#endif
                          );
}


/* Setup an IPsec route entry.
 * op is one of the ERO_* operators.
 */

// should be made static again once we fix initiate.c calling this directly!
bool raw_eroute(const ip_address *this_host,
                       const ip_subnet *this_client,
                       const ip_address *that_host,
                       const ip_subnet *that_client,
                       ipsec_spi_t cur_spi,
                       ipsec_spi_t new_spi,
                       int sa_proto,
                       unsigned int transport_proto,
                       enum eroute_type esatype,
                       const struct pfkey_proto_info *proto_info,
                       deltatime_t use_lifetime,
                       uint32_t sa_priority,
                       const struct sa_marks *sa_marks,
                       enum pluto_sadb_operations op,
                       const char *opname
#ifdef HAVE_LABELED_IPSEC
                       , const char *policy_label
#endif
                       )
{
        char text_said[SATOT_BUF + SATOT_BUF];
        bool result;

        switch (op) {
        case ERO_ADD:
        case ERO_ADD_INBOUND:
                set_text_said(text_said, that_host, new_spi, sa_proto);
                break;
        case ERO_DELETE:
        case ERO_DEL_INBOUND:
                set_text_said(text_said, that_host, cur_spi, sa_proto);
                break;
        case ERO_REPLACE:
        case ERO_REPLACE_INBOUND:
        {
                size_t w;

                set_text_said(text_said, that_host, cur_spi, sa_proto);
                w = strlen(text_said);
                text_said[w] = '>';
                set_text_said(text_said + w + 1, that_host, new_spi, sa_proto);
                break;
        }
        default:
                bad_case(op);
        }

       DBG(DBG_CONTROL | DBG_KERNEL,
            {
                    int sport = ntohs(portof(&this_client->addr));
                    int dport = ntohs(portof(&that_client->addr));
                    char mybuf[SUBNETTOT_BUF];
                    char peerbuf[SUBNETTOT_BUF];

                    subnettot(this_client, 0, mybuf, sizeof(mybuf));
                    subnettot(that_client, 0, peerbuf, sizeof(peerbuf));        /* OR: derived from that_client */
                    DBG_log("%s eroute %s:%d --%d-> %s:%d => %s (raw_eroute)",
                            opname, mybuf, sport, transport_proto, peerbuf,
                            dport,
                            text_said);
#ifdef HAVE_LABELED_IPSEC
                    if (policy_label != NULL)
                            DBG_log("policy security label %s", policy_label);
#endif
            });

        result = kernel_ops->raw_eroute(this_host, this_client,
                                        that_host, that_client,
                                        cur_spi, new_spi, sa_proto,
                                        transport_proto,
                                        esatype, proto_info,
                                        use_lifetime, sa_priority, sa_marks, op, text_said
#ifdef HAVE_LABELED_IPSEC
                                        , policy_label
#endif
                                        );

        DBG(DBG_CONTROL | DBG_KERNEL, DBG_log("raw_eroute result=%s",
                result ? "success" : "failed"));

        return result;
}


/* ------------------------------------------------------ */

/* programs/pluto/connections.h  */

/* kind of struct connection
 * Ordered (mostly) by concreteness.  Order is exploited.
 */

enum connection_kind {
        CK_GROUP,       /* policy group: instantiates to template */
        CK_TEMPLATE,    /* abstract connection, with wildcard */
        CK_PERMANENT,   /* normal connection */
        CK_INSTANCE,    /* instance of template, created for a particular attempt */
        CK_GOING_AWAY   /* instance being deleted -- don't delete again */
};

/* routing status.
 * Note: routing ignores source address, but erouting does not!
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE
 * or HAS_IPSEC_POLICY.
 */

/* note that this is assumed to be ordered! */
enum routing_t { 
        RT_UNROUTED,            /* unrouted */
        RT_UNROUTED_HOLD,       /* unrouted, but HOLD shunt installed */
        RT_ROUTED_ECLIPSED,     /* RT_ROUTED_PROSPECTIVE except bare HOLD or instance has eroute */
        RT_ROUTED_PROSPECTIVE,  /* routed, and prospective shunt installed */
        RT_ROUTED_HOLD,         /* routed, and HOLD shunt installed */
        RT_ROUTED_FAILURE,      /* routed, and failure-context shunt installed */
        RT_ROUTED_TUNNEL,       /* routed, and erouted to an IPSEC SA group */
        RT_UNROUTED_KEYED,       /* keyed, but not routed, on purpose */
};

struct end {
        struct id id;
        bool left;

        enum keyword_host host_type;
        char *host_addr_name;   /* string version from whack */
        ip_address
                host_addr,
                host_nexthop,
                host_srcip;
        ip_subnet client;

        bool key_from_DNS_on_demand;
        bool has_client;
        bool has_client_wildcard;
        bool has_port_wildcard;
        bool has_id_wildcards;
        char *updown;
        u_int16_t host_port;            /* where the IKE port is */
        bool host_port_specific;        /* if TRUE, then IKE ports are tested for */
        u_int16_t port;                 /* port number, if per-port keying */
        u_int8_t protocol;              /* transport-protocol number, if per-X keying */

        enum certpolicy sendcert;       /* whether or not to send the certificate */
        cert_t cert;                    /* end certificate */
        chunk_t ca;                     /* CA distinguished name of the end certificate's issuer */

        struct virtual_t *virt;

        bool xauth_server;
        bool xauth_client;
        char *username;
        char *xauth_password;
        ip_range pool_range;    /* store start of v4 addresspool */
        bool has_lease;         /* from address pool */
        bool modecfg_server;    /* Give local addresses to tunnel's end */
        bool modecfg_client;    /* request address for local end */
};


struct spd_route {
        struct spd_route *spd_next;
        struct end this;
        struct end that;
        so_serial_t eroute_owner;
        enum routing_t routing; /* level of routing in place */
        reqid_t reqid;
};

struct connection {
        char *name;
        char *connalias;
        lset_t policy;
        deltatime_t sa_ike_life_seconds;
        deltatime_t sa_ipsec_life_seconds;
        deltatime_t sa_rekey_margin;
        unsigned long sa_rekey_fuzz;
        unsigned long sa_keying_tries;
        uint32_t sa_priority;
        uint32_t sa_replay_window; /* Usually 32, KLIPS and XFRM/NETKEY support 64 */
                                   /* See also kernel_ops->replay_window */
        struct sa_marks sa_marks; /* contains a MARK values and MASK value for IPsec SA */
        char *vti_iface;
        bool vti_routing;
        unsigned long r_interval; /* initial retransmit time in msec, doubles each time */
        deltatime_t r_timeout; /* max time (in secs) for one packet exchange attempt */
        reqid_t sa_reqid;
        int encapsulation;

        /* RFC 3706 DPD */
        deltatime_t dpd_delay;          /* time between checks */
        deltatime_t dpd_timeout;        /* time after which we are dead */
        enum dpd_action dpd_action;     /* what to do when we die */

        bool nat_keepalive;             /* Suppress sending NAT-T Keep-Alives */
        bool initial_contact;           /* Send INITIAL_CONTACT (RFC-2407) payload? */
        bool cisco_unity;               /* Send Unity VID for cisco compatibility */
        bool fake_strongswan;           /* Send the unversioned strongswan VID */
        bool send_vendorid;             /* Send our vendorid? Security vs Debugging help */
        bool sha2_truncbug;
        enum ikev1_natt_policy ikev1_natt; /* whether or not to send IKEv1 draft/rfc NATT VIDs */

        /* Network Manager support */
#ifdef HAVE_NM
        bool nmconfigured;
#endif

#ifdef HAVE_LABELED_IPSEC
        bool labeled_ipsec;
        char *policy_label;
#endif

        /* Cisco interop: remote peer type */
        enum keyword_remotepeertype remotepeertype;

        enum keyword_xauthby xauthby;
        enum keyword_xauthfail xauthfail;

        bool forceencaps;                       /* always use NAT-T encap */

        char *log_file_name;                    /* name of log file */
        FILE *log_file;                         /* possibly open FILE */
        CIRCLEQ_ENTRY(connection) log_link;     /* linked list of open conns {} */
        bool log_file_err;                      /* only bitch once */

        struct spd_route spd;

        /* internal fields: */

        unsigned long instance_serial;
        policy_prio_t prio;
        bool instance_initiation_ok;            /* this is an instance of a policy that mandates initiate */
        enum connection_kind kind;
        const struct iface_port *interface;     /* filled in iff oriented */

        bool initiated;
        bool failed_ikev2;      /* tried ikev2, but failed */

        so_serial_t             /* state object serial number */
                newest_isakmp_sa,
                newest_ipsec_sa;

        lset_t extra_debugging;

        /* note: if the client is the gateway, the following must be equal */
        sa_family_t addr_family;        /* between gateways */
        sa_family_t tunnel_addr_family; /* between clients */

        /* if multiple policies, next one to apply */
        struct connection *policy_next;

        struct gw_info *gw_info;
        struct alg_info_esp *alg_info_esp;      /* ??? OK for AH too? */
        struct alg_info_ike *alg_info_ike;

        /*
         * The ALG_INFO converted to IKEv2 format.
         *
         * Since they are allocated on-demand so there's no need to
         * worry about copying them when a connection object gets
         * cloned.
         */
        struct ikev2_proposals *ike_proposals;
        struct ikev2_proposals *esp_or_ah_proposals;

        /* host_pair linkage */
        struct host_pair *host_pair;
        struct connection *hp_next;

        struct connection *ac_next;     /* all connections list link */

        enum send_ca_policy send_ca;
#ifdef XAUTH_HAVE_PAM
        pam_handle_t *pamh;             /*  PAM handle for that connection  */
#endif
        char *dnshostname;

        ip_address modecfg_dns1;
        ip_address modecfg_dns2;
        struct ip_pool *pool; /* IPv4 addresspool as a range, start end */
        char *cisco_dns_info; /* scratchpad for writing IP addresses */
        char *modecfg_domain;
        char *modecfg_banner;

        u_int8_t metric;        /* metric for tunnel routes */
        u_int16_t connmtu;      /* mtu for tunnel routes */
        u_int32_t statsval;     /* track what we have told statsd */
        u_int16_t nflog_group;  /* NFLOG group - 0 means disabled  */
};


/* state object: record the state of a (possibly nascent) SA
 *
 * Invariants (violated only during short transitions):
 * - each state object will be in statetable exactly once.
 * - each state object will always have a pending event.
 *   This prevents leaks.
 */
struct state {
        so_serial_t st_serialno;                /* serial number (for seniority)*/
        so_serial_t st_clonedfrom;              /* serial number of parent */

        pthread_mutex_t xauth_mutex;            /* per state xauth_mutex */
        pthread_t xauth_tid;                    /* per state XAUTH_RO thread id */
        bool has_pam_thread;                    /* per state PAM thread flag */

        bool st_ikev2;                          /* is this an IKEv2 state? */
        bool st_rekeytov2;                      /* true if this IKEv1 is about
                                                 * to be replaced with IKEv2
                                                 */

        struct connection *st_connection;       /* connection for this SA */
        int st_whack_sock;                      /* fd for our Whack TCP socket.
                                                 * Single copy: close when
                                                 * freeing struct.
                                                 */

        struct msg_digest *st_suspended_md;     /* suspended state-transition */
        const char        *st_suspended_md_func;
        int st_suspended_md_line;

        /* ... */
};


bool install_ipsec_sa(struct state *st, bool inbound_also)
{
        DBG(DBG_CONTROL, DBG_log("install_ipsec_sa() for #%lu: %s",
                                 st->st_serialno,
                                 inbound_also ?
                                 "inbound and outbound" : "outbound only"));

        enum routability rb = could_route(st->st_connection);

        switch (rb) {
        case route_easy:
        case route_unnecessary:
        case route_nearconflict:
                break;

        default:
                return FALSE;
        }

        /* (attempt to) actually set up the SA group */

        /* setup outgoing SA if we haven't already */
        if (!st->st_outbound_done) {
                if (!setup_half_ipsec_sa(st, FALSE))
                        return FALSE;

                DBG(DBG_KERNEL,
                    DBG_log("set up outgoing SA, ref=%u/%u", st->st_ref,
                            st->st_refhim));
                st->st_outbound_done = TRUE;
        }

        /* now setup inbound SA */
        if (st->st_ref == IPSEC_SAREF_NULL && inbound_also) {
                if (!setup_half_ipsec_sa(st, TRUE))
                        return FALSE;

                DBG(DBG_KERNEL,
                    DBG_log("set up incoming SA, ref=%u/%u", st->st_ref,
                            st->st_refhim));
        }

        if (rb == route_unnecessary)
                return TRUE;

        struct spd_route *sr = &st->st_connection->spd;

        if (st->st_connection->remotepeertype == CISCO && sr->spd_next != NULL)
                sr = sr->spd_next;

        /* for (sr = &st->st_connection->spd; sr != NULL; sr = sr->next) */
        for (; sr != NULL; sr = sr->spd_next) {
                DBG(DBG_CONTROL, DBG_log("sr for #%lu: %s",
                                         st->st_serialno,
                                         enum_name(&routing_story,
                                                   sr->routing)));

                /*
                 * if the eroute owner is not us, then make it us.
                 * See test co-terminal-02, pluto-rekey-01, pluto-unit-02/oppo-twice
                 */
                pexpect(sr->eroute_owner == SOS_NOBODY ||
                        sr->routing >= RT_ROUTED_TUNNEL);

                if (sr->eroute_owner != st->st_serialno &&
                    sr->routing != RT_UNROUTED_KEYED) {
                        if (!route_and_eroute(st->st_connection, sr, st)) {
                                delete_ipsec_sa(st);
                                /* XXX go and unroute any SRs that were successfully
                                 * routed already.
                                 */
                                return FALSE;
                        }
                }
        }

        /* XXX why is this needed? Skip the bogus original conn? */
        if (st->st_connection->remotepeertype == CISCO) {
                struct spd_route *srcisco = st->st_connection->spd.spd_next;

                if (srcisco != NULL) {
                        st->st_connection->spd.eroute_owner = srcisco->eroute_owner;
                        st->st_connection->spd.routing = srcisco->routing;
                }
        }

#ifdef USE_LINUX_AUDIT
        linux_audit_conn(st, LAK_CHILD_START);
#endif

        return TRUE;
}


/*
 * Set up one direction of the SA bundle
 */
static bool setup_half_ipsec_sa(struct state *st, bool inbound)
{
        /* Build an inbound or outbound SA */

        struct connection *c = st->st_connection;
        ip_subnet src, dst;
        ip_subnet src_client, dst_client;
        ipsec_spi_t inner_spi = 0;
        unsigned int proto = 0;
        enum eroute_type esatype = ET_UNSPEC;
        bool replace = inbound && (kernel_ops->get_spi != NULL);
        bool outgoing_ref_set = FALSE;
        bool incoming_ref_set = FALSE;
        IPsecSAref_t refhim = st->st_refhim;
        IPsecSAref_t new_refhim = IPSEC_SAREF_NULL;

        /* ... */

        if (inbound) {
                src.addr = c->spd.that.host_addr;
                dst.addr = c->spd.this.host_addr;
                src_client = c->spd.that.client;
                dst_client = c->spd.this.client;
        } else {
                src.addr = c->spd.this.host_addr,
                dst.addr = c->spd.that.host_addr;
                src_client = c->spd.this.client;
                dst_client = c->spd.that.client;
        }

        /* ... */

        /*
         * Add an inbound eroute to enforce an arrival check.
         *
         * If inbound, and policy does not specify DISABLEARRIVALCHECK,
         * ??? and some more mysterious conditions,
         * tell KLIPS to enforce the IP addresses appropriate for this tunnel.
         * Note reversed ends.
         * Not much to be done on failure.
         */
        if (inbound && (c->policy & POLICY_DISABLEARRIVALCHECK) == 0 &&
            (kernel_ops->inbound_eroute ? c->spd.eroute_owner == SOS_NOBODY :
             encapsulation == ENCAPSULATION_MODE_TUNNEL))
             {
                /* ... */

                /*
                 * ??? why is encapsulation overwitten ONLY if
                 * kernel_ops->inbound_eroute?
                 */
                if (kernel_ops->inbound_eroute &&
                    encapsulation == ENCAPSULATION_MODE_TUNNEL) {
                        proto_info[0].encapsulation =
                                ENCAPSULATION_MODE_TUNNEL;
                        for (i = 1; proto_info[i].proto; i++)
                                proto_info[i].encapsulation =
                                        ENCAPSULATION_MODE_TRANSPORT;
                }

                /* MCR - should be passed a spd_eroute structure here */
                /* note: this and that are intentionally reversed */
                if (!raw_eroute(&c->spd.that.host_addr,         /* this_host */
                                  &c->spd.that.client,          /* this_client */
                                  &c->spd.this.host_addr,       /* that_host */
                                  &c->spd.this.client,          /* that_client */
                                  inner_spi,                    /* current spi - might not be used? */
                                  inner_spi,                    /* new spi */
                                  proto,                        /* SA proto */
                                  c->spd.this.protocol,         /* transport_proto */
                                  esatype,                      /* esatype */
                                  proto_info,                   /* " */
                                  deltatime(0),                 /* lifetime */
                                  c->sa_priority,               /* IPsec SA prio */
                                  &c->sa_marks,                 /* IPsec SA marks */
                                  ERO_ADD_INBOUND,              /* op */
                                  "add inbound"                 /* opname */
#ifdef HAVE_LABELED_IPSEC
                                  , st->st_connection->policy_label
#endif
                                  )) {
                        libreswan_log("raw_eroute() in setup_half_ipsec_sa() failed to add inbound");
                }

}

bool trap_connection(struct connection *c)
{
        enum routability r = could_route(c);

        switch (r) {
        case route_impossible:
                return FALSE;

        case route_easy:
        case route_nearconflict:
                /* RT_ROUTED_TUNNEL is treated specially: we don't override
                 * because we don't want to lose track of the IPSEC_SAs etc.
                 * ??? The test treats RT_UNROUTED_KEYED specially too.
                 */
                if (c->spd.routing < RT_ROUTED_TUNNEL)
                        return route_and_eroute(c, &c->spd, NULL);

                return TRUE;

        case route_farconflict:
                return FALSE;

        case route_unnecessary:
                return TRUE;
        default:
                bad_case(r);
        }
}

/*
 * Find the connection to connection c's peer's client with the
 * largest value of .routing.  All other things being equal,
 * preference is given to c.  If none is routed, return NULL.
 *
 * If erop is non-null, set *erop to a connection sharing both
 * our client subnet and peer's client subnet with the largest value
 * of .routing.  If none is erouted, set *erop to NULL.
 *
 * The return value is used to find other connections sharing a route.
 * *erop is used to find other connections sharing an eroute.
 */
struct connection *route_owner(struct connection *c,
                        const struct spd_route *cur_spd,
                        struct spd_route **srp,
                        struct connection **erop,
                        struct spd_route **esrp)
{
        /* ... */


        struct connection
                *best_ro = c,
                *best_ero = c;
        struct spd_route *best_sr = NULL,
                *best_esr = NULL;
        enum routing_t best_routing = cur_spd->routing,
                best_erouting = best_routing;

        struct connection *d;

        for (d = connections; d != NULL; d = d->ac_next) {

                /* ... */

                for (srd = &d->spd; srd != NULL; srd = srd->spd_next) {
                        if (srd->routing == RT_UNROUTED)
                                continue;

                        const struct spd_route *src;

                        for (src = &c->spd; src != NULL; src = src->spd_next) {
                                if (src == srd)
                                        continue;

                                /* ... OR: adjust best_routing/best_erouting to best match */
                        }
        }

        DBG(DBG_CONTROL, {
                char cib[CONN_INST_BUF];
                err_t m = builddiag("route owner of \"%s\"%s %s:",
                                c->name,
                                fmt_conn_instance(c, cib),
                                enum_name(&routing_story,
                                        cur_spd->routing));

                if (!routed(best_routing)) {
                        m = builddiag("%s NULL", m);
                } else if (best_ro == c) {
                        m = builddiag("%s self", m);
                } else {
                        m = builddiag("%s \"%s\"%s %s", m,
                                best_ro->name,
                                fmt_conn_instance(best_ro, cib),
                                enum_name(&routing_story, best_routing));
                }

                if (erop != NULL) {
                        m = builddiag("%s; eroute owner:", m);
                        if (!erouted(best_ero->spd.routing)) {
                                m = builddiag("%s NULL", m);
                        } else if (best_ero == c) {
                                m = builddiag("%s self", m);
                        } else {
                                m = builddiag("%s \"%s\"%s %s", m,
                                        best_ero->name,
                                        fmt_conn_instance(best_ero, cib),
                                        enum_name(&routing_story,
                                                best_ero->spd.routing));
                        }
                }

                DBG_log("%s", m);
        });

        if (erop != NULL)
                *erop = erouted(best_erouting) ? best_ero : NULL;

        if (srp != NULL ) {
                *srp = best_sr;
                if (esrp != NULL )
                        *esrp = best_esr;
        }

        return routed(best_routing) ? best_ro : NULL;
}

/*
 * Add/replace/delete a shunt eroute.
 *
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 */
static bool shunt_eroute(const struct connection *c,
                         const struct spd_route *sr,
                         enum routing_t rt_kind,
                         enum pluto_sadb_operations op,
                         const char *opname)
{
        DBG(DBG_CONTROL, DBG_log("shunt_eroute() called for connection '%s' to '%s' for rt_kind '%s'",
                        c->name, opname, enum_name(&routing_story, rt_kind)));
        if (kernel_ops->shunt_eroute != NULL) {
                return kernel_ops->shunt_eroute(c, sr, rt_kind, op, opname);
        }

        loglog(RC_COMMENT, "no shunt_eroute implemented for %s interface",
               kernel_ops->kern_name);
        return TRUE;
}

static bool sag_eroute(const struct state *st,
                       const struct spd_route *sr,
                       enum pluto_sadb_operations op,
                       const char *opname)
{
        pexpect(kernel_ops->sag_eroute != NULL);
        if (kernel_ops->sag_eroute != NULL)
                return kernel_ops->sag_eroute(st, sr, op, opname); /* OR: HERE: calls netlink_raw_eroute() */

        return FALSE;
}

/*
 * netlink_raw_eroute
 *
 * @param this_host ip_address
 * @param this_client ip_subnet
 * @param that_host ip_address
 * @param that_client ip_subnet
 * @param spi
 * @param sa_proto int (4=tunnel, 50=esp, 108=ipcomp, etc ...)
 * @param transport_proto unsigned int Contains protocol
 *      (6=tcp, 17=udp, etc...)
 * @param esatype int
 * @param pfkey_proto_info proto_info
 * @param use_lifetime monotime_t (Currently unused)
 * @param pluto_sadb_opterations sadb_op (operation - ie: ERO_DELETE)
 * @param text_said char
 * @return boolean True if successful
 */
static bool netlink_raw_eroute(const ip_address *this_host,
                        const ip_subnet *this_client,
                        const ip_address *that_host,
                        const ip_subnet *that_client,
                        ipsec_spi_t cur_spi,    /* current SPI */
                        ipsec_spi_t new_spi,    /* new SPI */
                        int sa_proto,
                        unsigned int transport_proto,
                        enum eroute_type esatype,
                        const struct pfkey_proto_info *proto_info,
                        deltatime_t use_lifetime UNUSED,
                        uint32_t sa_priority, 
                        const struct sa_marks *sa_marks,
                        enum pluto_sadb_operations sadb_op,
                        const char *text_said
#ifdef HAVE_LABELED_IPSEC 
                        , const char *policy_label
#endif
        )
{
        struct {
                struct nlmsghdr n;
                union {
                        struct xfrm_userpolicy_info p;
                        struct xfrm_userpolicy_id id;
                } u;
                char data[MAX_NETLINK_DATA_SIZE];
        } req;
        int shift;
        int dir;
        int family;
        int policy;
        bool ok;
        bool enoent_ok;
        ip_subnet local_client;
        int satype = 0;

        policy = IPSEC_POLICY_IPSEC;

        switch (esatype) {
        /* ... */
        case ET_IPCOMP:
                satype = SADB_X_SATYPE_IPCOMP;
                break;
        /* ... */
        }

        if (satype != 0) {
                DBG(DBG_KERNEL,
                        DBG_log("satype(%d) is not used in netlink_raw_eroute.",
                                satype));
        }

}

/* Install a route and then a prospective shunt eroute or an SA group eroute.
 * Assumption: could_route gave a go-ahead.
 * Any SA Group must have already been created.
 * On failure, steps will be unwound.
 */
bool route_and_eroute(struct connection *c,
                      struct spd_route *sr,
                      struct state *st)
{
        bool eroute_installed = FALSE,
             firewall_notified = FALSE,
             route_installed = FALSE;

#ifdef IPSEC_CONNECTION_LIMIT
        bool new_eroute = FALSE;
#endif

        struct spd_route *esr, *rosr;
        struct connection *ero,
                *ro = route_owner(c, sr, &rosr, &ero, &esr);    /* who, if anyone, owns our eroute? */

        DBG(DBG_CONTROLMORE,
            DBG_log("route_and_eroute with c: %s (next: %s) ero:%s esr:{%p} ro:%s rosr:{%p} and state: #%lu",
                    c->name,
                    (c->policy_next ? c->policy_next->name : "none"),
                    ero == NULL ? "null" : ero->name,
                    esr,
                    ro == NULL ? "null" : ro->name,
                    rosr,
                    st == NULL ? 0 : st->st_serialno));                         /* OR: HERE */

        /* look along the chain of policies for one with the same name */

        /* ... */

       if (bspp != NULL || ero != NULL) {
                /* We're replacing an eroute */

                /* ... */

        } else {
                /* we're adding an eroute */
#ifdef IPSEC_CONNECTION_LIMIT
                if (num_ipsec_eroute == IPSEC_CONNECTION_LIMIT) {
                        loglog(RC_LOG_SERIOUS,
                               "Maximum number of IPsec connections reached (%d)",
                               IPSEC_CONNECTION_LIMIT);
                        return FALSE;
                }
                new_eroute = TRUE;
#endif

                /* if no state provided, then install a shunt for later */
                if (st == NULL) {
                        eroute_installed = shunt_eroute(c, sr,
                                                        RT_ROUTED_PROSPECTIVE,
                                                        ERO_ADD, "add");
                } else {
                        eroute_installed = sag_eroute(st, sr, ERO_ADD, "add");  /* OR: HERE */
                }
        }

        /* notify the firewall of a new tunnel */

        if (eroute_installed) {
                /* do we have to notify the firewall?  Yes, if we are installing
                 * a tunnel eroute and the firewall wasn't notified
                 * for a previous tunnel with the same clients.  Any Previous
                 * tunnel would have to be for our connection, so the actual
                 * test is simple.
                 */
                firewall_notified = st == NULL ||                       /* not a tunnel eroute */
                                    sr->eroute_owner != SOS_NOBODY ||   /* already notified */
                                    do_command(c, sr, "up", st);        /* go ahead and notify */
        }

        /* install the route */

        DBG(DBG_CONTROL,
            DBG_log("route_and_eroute: firewall_notified: %s",
                    firewall_notified ? "true" : "false"));
        if (!firewall_notified) {
                /* we're in trouble -- don't do routing */
        } else if (ro == NULL) {
                /* a new route: no deletion required, but preparation is */
                if (!do_command(c, sr, "prepare", st))
                        DBG(DBG_CONTROL,
                            DBG_log("prepare command returned an error"));
                route_installed = do_command(c, sr, "route", st);
                if (!route_installed)
                        DBG(DBG_CONTROL,
                            DBG_log("route command returned an error"));
        } else if (routed(sr->routing) ||
                   routes_agree(ro, c)) {
                route_installed = TRUE; /* nothing to be done */
        } else {
                /* ... */
        }

        /* all done -- clean up */
        if (route_installed) {
                /* Success! */

                if (bspp != NULL) {
                        free_bare_shunt(bspp);
                } else if (ero != NULL && ero != c) {
                        /* check if ero is an ancestor of c. */
                        struct connection *ero2;

                        for (ero2 = c; ero2 != NULL && ero2 != c;
                             ero2 = ero2->policy_next)
                                ;

                        if (ero2 == NULL) {
                                /* By elimination, we must be eclipsing ero.  Checked above. */
                                if (ero->spd.routing != RT_ROUTED_ECLIPSED) {
                                        ero->spd.routing = RT_ROUTED_ECLIPSED;
                                        eclipse_count++;
                                }
                        }
                }
                if (st == NULL) {
                        passert(sr->eroute_owner == SOS_NOBODY);
                        sr->routing = RT_ROUTED_PROSPECTIVE;
                } else {
                        sr->routing = RT_ROUTED_TUNNEL;

                        DBG(DBG_CONTROL, {
                                    char cib[CONN_INST_BUF];
                                    DBG_log("route_and_eroute: instance \"%s\"%s, setting eroute_owner {spd=%p,sr=%p} to #%lu (was #%lu) (newest_ipsec_sa=#%lu)",
                                            st->st_connection->name,
                                            fmt_conn_instance(st->st_connection,
                                                              cib),
                                            &st->st_connection->spd, sr,
                                            st->st_serialno,
                                            sr->eroute_owner,
                                            st->st_connection->newest_ipsec_sa);
                            });
                        sr->eroute_owner = st->st_serialno;
                        /* clear host shunts that clash with freshly installed route */
                        clear_narrow_holds(&sr->this.client, &sr->that.client,
                                           sr->this.protocol);
                }

#ifdef IPSEC_CONNECTION_LIMIT
                if (new_eroute) {
                        num_ipsec_eroute++;
                        loglog(RC_COMMENT,
                               "%d IPsec connections are currently being managed",
                               num_ipsec_eroute);
                }
#endif

                return TRUE;
        } else {
                /* Failure!  Unwind our work. */


                /* ... */

                return FALSE;
        }
}
