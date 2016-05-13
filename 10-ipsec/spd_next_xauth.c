/*
 * STATE_MODE_CFG_R1:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status modecfg_inR1(struct msg_digest *md)
{

        /* ... */


                        case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
                        {
                                /*
                                 * ??? this really should be parsed by packet
                                 * routines
                                 */
                                size_t len = pbs_left(&strattr);
                                struct connection *c = st->st_connection;
                                struct spd_route *last_spd = &c->spd;

                                /* OR: we see this in our logs */
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

                                        /* OR: this creates the new spd_route; clones the local end's params? */
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

                                        /* OR: we see the following in our logs: caddr and hence that.client are 0.0.0.0/0 */

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

                                        /* OR: append our new spd_route to the previous one */
                                        tmp_spd->spd_next = NULL;
                                        last_spd->spd_next = tmp_spd;
                                        last_spd = tmp_spd;
                                }

