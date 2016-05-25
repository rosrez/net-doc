/* ./include/ietf_constants.h */

/* Mode Config attribute values */
#define INTERNAL_IP4_ADDRESS 1
#define INTERNAL_IP4_NETMASK 2
#define INTERNAL_IP4_DNS 3
#define INTERNAL_IP4_NBNS 4 /* unused by us, WINS is long dead */
#define INTERNAL_ADDRESS_EXPIRY 5
#define INTERNAL_IP4_DHCP 6
#define APPLICATION_VERSION 7
#define INTERNAL_IP6_ADDRESS 8
#define INTERNAL_IP6_NETMASK 9
#define INTERNAL_IP6_DNS 10
#define INTERNAL_IP6_NBNS 11
#define INTERNAL_IP6_DHCP 12
#define INTERNAL_IP4_SUBNET 13
#define SUPPORTED_ATTRIBUTES 14
#define INTERNAL_IP6_SUBNET 15
#define MIP6_HOME_PREFIX 16
#define INTERNAL_IP6_LINK 17
#define INTERNAL_IP6_PREFIX 18
#define HOME_AGENT_ADDRESS 19


/* Unity (Cisco) Mode Config attribute values */
#define MODECFG_BANNER 28672
#define CISCO_SAVE_PW 28673
#define MODECFG_DOMAIN 28674
#define CISCO_SPLIT_DNS 28675
#define CISCO_SPLIT_INC 28676           /* OR: the offending attribute */
#define CISCO_UDP_ENCAP_PORT 28677
#define CISCO_SPLIT_EXCLUDE 28678
#define CISCO_DO_PFS 28679
#define CISCO_FW_TYPE 28680
#define CISCO_BACKUP_SERVER 28681
#define CISCO_DDNS_HOSTNAME 28682
#define CISCO_UNKNOWN_SEEN_ON_IPHONE 28683


/* lib/libswan/constants.c */



/* IKEv1 XAUTH-STATUS attribute names  */
static const char *const modecfg_attr_name_draft[] = {
        "INTERNAL_IP4_ADDRESS", /* 1 */
        "INTERNAL_IP4_NETMASK",
        "INTERNAL_IP4_DNS",
        "INTERNAL_IP4_NBNS",
        "INTERNAL_ADDRESS_EXPIRY",
        "INTERNAL_IP4_DHCP",
        "APPLICATION_VERSION",
        "INTERNAL_IP6_ADDRESS",
        "INTERNAL_IP6_NETMASK",
        "INTERNAL_IP6_DNS",
        "INTERNAL_IP6_NBNS",
        "INTERNAL_IP6_DHCP",
        "INTERNAL_IP4_SUBNET",  /* 13 */
        "SUPPORTED_ATTRIBUTES",
        "INTERNAL_IP6_SUBNET",
        "MIP6_HOME_PREFIX",
        "INTERNAL_IP6_LINK",
        "INTERNAL_IP6_PREFIX",
        "HOME_AGENT_ADDRESS",   /* 19 */
};

static enum_names modecfg_attr_names_draft = {
        INTERNAL_IP4_ADDRESS,
        HOME_AGENT_ADDRESS,
        modecfg_attr_name_draft,
        NULL
};

static const char *const modecfg_cisco_attr_name[] = {
        "MODECFG_BANNER",       /* 28672 */
        "CISCO_SAVE_PW",
        "MODECFG_DOMAIN",
        "CISCO_SPLIT_DNS",
        "CISCO_SPLIT_INC",
        "CISCO_UDP_ENCAP_PORT",
        "CISCO_SPLIT_EXCLUDE",
        "CISCO_DO_PFS",
        "CISCO_FW_TYPE",
        "CISCO_BACKUP_SERVER",
        "CISCO_DDNS_HOSTNAME",
        "CISCO_UNKNOWN_SEEN_ON_IPHONE", /* 28683 */
};
static enum_names modecfg_cisco_attr_names = {
        MODECFG_BANNER,
        CISCO_UNKNOWN_SEEN_ON_IPHONE,
        modecfg_cisco_attr_name,
        NULL
};


/* programs/pluto/packet.h */

/* ISAKMP Data Attribute (generic representation within payloads)
 * layout from RFC 2408 "ISAKMP" section 3.3
 * This is not a payload type.
 * In TLV format, this is followed by a value field.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !A!       Attribute Type        !    AF=0  Attribute Length     !
 * !F!                             !    AF=1  Attribute Value      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * .                   AF=0  Attribute Value                       .
 * .                   AF=1  Not Transmitted                       .
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_attribute {
        /* The high order bit of isaat_af_type is the Attribute Format
         * If it is off, the format is TLV: lv is the length of the following
         * attribute value.
         * If it is on, the format is TV: lv is the value of the attribute.
         * ISAKMP_ATTR_AF_MASK is the mask in host form.
         *
         * The low order 15 bits of isaat_af_type is the Attribute Type.
         * ISAKMP_ATTR_RTYPE_MASK is the mask in host form.
         */
        u_int16_t isaat_af_type;        /* high order bit: AF; lower 15: rtype */
        u_int16_t isaat_lv;             /* Length or value */
};



/* ./programs/pluto/ikev1_xauth.c */


/*
 * STATE_MODE_CFG_R1:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status modecfg_inR1(struct msg_digest *md)
{
        struct state *const st = md->st;
        struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->payload.mode_attribute;
        pb_stream *attrs = &md->chain[ISAKMP_NEXT_MCFG_ATTR]->pbs;
        lset_t resp = LEMPTY;

        DBG(DBG_CONTROL, DBG_log("modecfg_inR1: received mode cfg reply"));

        st->st_msgid_phase15 = md->hdr.isa_msgid;
        CHECK_QUICK_HASH(md,
                         xauth_mode_cfg_hash(hash_val, hash_pbs->roof,
                                             md->message_pbs.roof,
                                             st),
                         "MODECFG-HASH", "MODE R1");

        switch (ma->isama_type) {
        default:
        {
                libreswan_log(
                        "Expecting ISAKMP_CFG_ACK or ISAKMP_CFG_REPLY, got %x instead.",
                        ma->isama_type);
                return STF_IGNORE;
                break;
        }

        case ISAKMP_CFG_ACK:
                /* CHECK that ACK has been received. */
                while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
                        struct isakmp_attribute attr;

                        if (!in_struct(&attr,
                                       &isakmp_xauth_attribute_desc,
                                       attrs, NULL)) {
                                /* reject malformed */
                                return STF_FAIL;
                        }

                        switch (attr.isaat_af_type) {
                        case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
                        case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
                        case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
                        case INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TLV:
                                resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
                                break;

                        case INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
                                /* ignore */
                                break;
                        case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
                        case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
                        case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
                                /* ignore - we will always send/receive these */
                                break;

                        default:
                                log_bad_attr("modecfg", &modecfg_attr_names, attr.isaat_af_type);
                                break;
                        }
                }
                break;

        case ISAKMP_CFG_REPLY:
                while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
                        struct isakmp_attribute attr;
                        pb_stream strattr;

                        if (!in_struct(&attr,
                                       &isakmp_xauth_attribute_desc,
                                       attrs, &strattr)) {
                                /* reject malformed */
                                return STF_FAIL;
                        }

                        switch (attr.isaat_af_type) {

                        case INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
                        {
                                struct connection *c = st->st_connection;
                                ip_address a;
                                char caddr[SUBNETTOT_BUF];

                                u_int32_t *ap =
                                        (u_int32_t *)(strattr.cur);
                                a.u.v4.sin_family = AF_INET;
                                memcpy(&a.u.v4.sin_addr.s_addr, ap,
                                       sizeof(a.u.v4.sin_addr.s_addr));
                                addrtosubnet(&a, &c->spd.this.client);

                                /* make sure that the port info is zeroed */
                                setportof(0, &c->spd.this.client.addr);

                                c->spd.this.has_client = TRUE;
                                subnettot(&c->spd.this.client, 0,
                                          caddr, sizeof(caddr));
                                loglog(RC_INFORMATIONAL,
                                        "Received IPv4 address: %s",
                                        caddr);

                                if (addrbytesptr(&c->spd.this.host_srcip,
                                                 NULL) == 0 ||
                                    isanyaddr(&c->spd.this.host_srcip))
                                {
                                        DBG(DBG_CONTROL, DBG_log(
                                                "setting ip source address to %s",
                                                caddr));
                                        c->spd.this.host_srcip = a;
                                }
                                resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
                                break;
                        }


                       case INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
                        {
                                ip_address a;
                                ipstr_buf b;
                                u_int32_t *ap = (u_int32_t *)(strattr.cur);

                                a.u.v4.sin_family = AF_INET;
                                memcpy(&a.u.v4.sin_addr.s_addr, ap,
                                       sizeof(a.u.v4.sin_addr.s_addr));

                                DBG(DBG_CONTROL, DBG_log("Received IP4 NETMASK %s",
                                        ipstr(&a, &b)));
                                resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
                                break;
                        }

                        case INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
                        {
                                /* ..... */
                                break;
                        }

                        case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
                        {
                                /*
                                 * ??? this really should be parsed by packet
                                 * routines
                                 */
                                size_t len = pbs_left(&strattr);
                                struct connection *c = st->st_connection;
                                struct spd_route *last_spd = &c->spd;

                                DBG(DBG_CONTROL, DBG_log("Received Cisco Split tunnel route(s)"));
                                if (!last_spd->that.has_client) {
                                        ip_address any;

                                        passert(last_spd->spd_next == NULL);
                                        anyaddr(AF_INET, &any);
                                        initsubnet(&any, 0, '0',
                                                &last_spd->that.client);
                                        last_spd->that.has_client = TRUE;
                                        last_spd->that.has_client_wildcard =
                                                FALSE;
                                }

                                while (last_spd->spd_next != NULL) {
                                        /* ??? we should print out spd */
                                        last_spd = last_spd->spd_next;
                                }

                                /*
                                 * See diagram in modecfg_resp's
                                 * case CISCO_SPLIT_INC.
                                 * The 14 is explained there.
                                 */


                                while (len >= 14) {
                                        u_int32_t *ap =
                                                (u_int32_t *)(strattr.cur);
                                        struct spd_route *tmp_spd =
                                                clone_thing(c->spd,
                                                            "remote subnets policies");
                                        ip_address a;
                                        char caddr[SUBNETTOT_BUF];

                                        tmp_spd->this.id.name = empty_chunk;
                                        tmp_spd->that.id.name = empty_chunk;

                                        tmp_spd->this.host_addr_name = NULL;
                                        tmp_spd->that.host_addr_name = NULL;

                                        /* grab 4 octet IP address */
                                        a.u.v4.sin_family = AF_INET;
                                        memcpy(&a.u.v4.sin_addr.s_addr,
                                               ap,
                                               sizeof(a.u.v4.sin_addr.
                                                      s_addr));

                                        addrtosubnet(&a, &tmp_spd->that.client);

                                        len -= sizeof(a.u.v4.sin_addr.s_addr);
                                        strattr.cur +=
                                                sizeof(a.u.v4.sin_addr.s_addr);

                                        /* grab 4 octet address mask */
                                        ap = (u_int32_t *)(strattr.cur);
                                        a.u.v4.sin_family = AF_INET;
                                        memcpy(&a.u.v4.sin_addr.s_addr,
                                               ap,
                                               sizeof(a.u.v4.sin_addr.s_addr));

                                        tmp_spd->that.client.maskbits =
                                                masktocount(&a);
                                        len -= sizeof(a.u.v4.sin_addr.s_addr);
                                        strattr.cur +=
                                                sizeof(a.u.v4.sin_addr.s_addr);

                                        /* set port to 0 (??? surely default) */
                                        setportof(0,
                                                  &tmp_spd->that.client.addr);

                                        /* throw away 6 octets of who knows what */
                                        len -= 6;
                                        strattr.cur += 6;

                                        subnettot(
                                                &tmp_spd->that.client,
                                                0,
                                                caddr,
                                                sizeof(caddr));

                                        loglog(RC_INFORMATIONAL,
                                                "Received subnet %s",
                                                caddr);

                                        tmp_spd->this.cert.ty = CERT_NONE;
                                        tmp_spd->that.cert.ty = CERT_NONE;

                                        tmp_spd->this.ca.ptr = NULL;
                                        tmp_spd->that.ca.ptr = NULL;

                                        tmp_spd->this.virt = NULL;
                                        tmp_spd->that.virt = NULL;

                                        unshare_connection_end(&tmp_spd->this);
                                        unshare_connection_end(&tmp_spd->that);

                                        tmp_spd->spd_next = NULL;
                                        last_spd->spd_next = tmp_spd;
                                        last_spd = tmp_spd;
                                }

                                if (len != 0) {
                                        libreswan_log("ignoring %d unexpected octets at end of CISCO_SPLIT_INC attribute",
                                                (int)len);
                                }
                                /*
                                 * ??? this won't work because CISCO_SPLIT_INC is way bigger than LELEM_ROOF
                                 * resp |= LELEM(attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
                                 */
                                break;
                        }

