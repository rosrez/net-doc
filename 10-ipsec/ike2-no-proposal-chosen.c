/*
 SYMPTOM:
 Jun 15 11:09:13 localhost pluto[4122]: | ikev2_child_sa_respond returned STF_FAIL with v2N_NO_PROPOSAL_CHOSEN
 Jun 15 11:09:13 localhost pluto[4122]: | ikev2_parent_inI2outR2_tail returned STF_FAIL with v2N_NO_PROPOSAL_CHOSEN
 */

/* programs/pluto/ikev2_parent.c */

static stf_status ikev2_parent_inI2outR2_auth_tail(struct msg_digest *md,
                bool pam_status)
{
        struct state *const st = md->st;
        struct connection *const c = st->st_connection;
        unsigned char idhash_out[MAX_DIGEST_LEN];
        unsigned char *authstart;
        unsigned int np;


        authstart = reply_stream.cur;
        /* send response */
        {

                DBG(DBG_CONTROLMORE,
                    DBG_log("going to assemble AUTH payload"));


                /* now send AUTH payload */
                {
                        stf_status authstat = ikev2_send_auth(c, st,
                                                              ORIGINAL_RESPONDER, np,
                                                              idhash_out,
                                                              &e_pbs_cipher);

                        if (authstat != STF_OK)
                                return authstat;
                }


                if (np == ISAKMP_NEXT_v2SA || np == ISAKMP_NEXT_v2CP) {
                        /* must have enough to build an CHILD_SA */
                        stf_status ret = ikev2_child_sa_respond(md, ORIGINAL_RESPONDER,
                                                     &e_pbs_cipher,
                                                     ISAKMP_v2_AUTH);

                        /* note: st: parent; md->st: child */

                        if (ret > STF_FAIL) {
                                int v2_notify_num = ret - STF_FAIL;

                                DBG(DBG_CONTROL,
                                    DBG_log("ikev2_child_sa_respond returned STF_FAIL with %s",
                                            enum_name(&ikev2_notify_names,
                                                      v2_notify_num)));
                                np = ISAKMP_NEXT_v2NONE; /* use some day if we built a complete packet */
                                return ret; /* we should continue building a valid reply packet */
                        } else if (ret != STF_OK) {
                                DBG_log("ikev2_child_sa_respond returned %s",
                                        enum_name(&stfstatus_name, ret));
                                np = ISAKMP_NEXT_v2NONE; /* use some day if we built a complete packet */
                                return ret; /* we should continue building a valid reply packet */
                        }
                }

                /* ..... */

        }

}

/* SYMPTOM:
Jun 15 11:09:13 localhost pluto[4122]: |   ikev2_evaluate_connection_fit evaluating our conn="home-work-cacert" I=0.0.0.0/32:0/0 R=192.168.1.5/32:0/0 (virt) to their:
Jun 15 11:09:13 localhost pluto[4122]: |     tsi[0]=192.168.1.226/192.168.1.226 proto=0 portrange 0-65535, tsr[0]=192.168.1.5/192.168.1.5 proto=0 portrange 0-65535
Jun 15 11:09:13 localhost pluto[4122]: | prefix fitness rejected c home-work-cacert c->name

Jun 15 11:09:13 localhost pluto[4122]: | find_host_pair: comparing 192.168.1.5:500 to 0.0.0.0:500
Jun 15 11:09:13 localhost pluto[4122]: | find_host_pair: comparing 192.168.1.5:500 to 192.168.1.226:500
Jun 15 11:09:13 localhost pluto[4122]: |   checking hostpair 192.168.1.5/32 -> 0.0.0.0/32 is found
Jun 15 11:09:13 localhost pluto[4122]: |    match_id a=C=US, ST=Rhode Island, O=MyCorp CA, OU=Software, CN=Work
Jun 15 11:09:13 localhost pluto[4122]: |             b=C=US, ST=Rhode Island, O=MyCorp CA, OU=Software, CN=Work
Jun 15 11:09:13 localhost pluto[4122]: |    results  matched
Jun 15 11:09:13 localhost pluto[4122]: | trusted_ca_nss: trustee A = '(empty)'
Jun 15 11:09:13 localhost pluto[4122]: | trusted_ca_nss: trustor B = '(empty)'
Jun 15 11:09:13 localhost pluto[4122]: |   ikev2_evaluate_connection_fit evaluating our conn="home-work-cacert" I=0.0.0.0/32:0/0 R=192.168.1.5/32:0/0 (virt) to their:
Jun 15 11:09:13 localhost pluto[4122]: |     tsi[0]=192.168.1.226/192.168.1.226 proto=0 portrange 0-65535, tsr[0]=192.168.1.5/192.168.1.5 proto=0 portrange 0-65535
Jun 15 11:09:13 localhost pluto[4122]: | prefix fitness rejected d home-work-cacert
*/

/*
 * find the best connection and, if it is AUTH exchange, create the child state
 */
static stf_status ikev2_create_responder_child_state(
        const struct msg_digest *md,
        struct state **ret_cst, /* where to return child state */
        enum original_role role, enum isakmp_xchg_types isa_xchg)
{
        struct connection *c = md->st->st_connection;

        /* ??? is 16 an undocumented limit? */
        struct traffic_selector tsi[16], tsr[16];
        const int tsi_n = ikev2_parse_ts(md->chain[ISAKMP_NEXT_v2TSi],
                tsi, elemsof(tsi));
        const int tsr_n = ikev2_parse_ts(md->chain[ISAKMP_NEXT_v2TSr],
                tsr, elemsof(tsr));

       /* best so far */
        int bestfit_n = -1;
        int bestfit_p = -1;
        int bestfit_pr = -1;
        const struct spd_route *bsr = NULL;     /* best spd_route so far */

        int best_tsi_i = -1;
        int best_tsr_i = -1;

        *ret_cst = NULL;        /* no child state yet */

        /* ??? not very clear diagnostic for our user */
        if (tsi_n < 0 || tsr_n < 0)
                return STF_FAIL + v2N_TS_UNACCEPTABLE;

        /* find best spd in c */
        const struct spd_route *sra;

        for (sra = &c->spd; sra != NULL; sra = sra->spd_next) {
                int bfit_n = ikev2_evaluate_connection_fit(c, sra, role, tsi,
                                tsr, tsi_n, tsr_n);

               if (bfit_n > bestfit_n) {

                        /* ..... OXR: port fitness match check, remember best fit so far, etc. */

               } else {
                        DBG(DBG_CONTROLMORE,
                            DBG_log("prefix fitness rejected c %s c->name", c->name));
               }
        }

        /*
         * ??? the use of hp looks nonsensical.
         * Either the first non-empty host_pair should be used
         * (like the current code) and the following should
         * be broken into two loops: first find the non-empty
         * host_pair list, second look through the host_pair list.
         * OR
         * what's really meant is look at the host_pair for
         * each sra, something that matches the current
         * nested loop structure but not what it actually does.
         */

        struct connection *b = c;       /* best connection so far */
        const struct host_pair *hp = NULL;

/*
 * OXR:
Jun 15 11:09:13 localhost pluto[4122]: | find_host_pair: comparing 192.168.1.5:500 to 0.0.0.0:500
Jun 15 11:09:13 localhost pluto[4122]: | find_host_pair: comparing 192.168.1.5:500 to 192.168.1.226:500
Jun 15 11:09:13 localhost pluto[4122]: |   checking hostpair 192.168.1.5/32 -> 0.0.0.0/32 is found
Jun 15 11:09:13 localhost pluto[4122]: |    match_id a=C=US, ST=Rhode Island, O=MyCorp CA, OU=Software, CN=Work
Jun 15 11:09:13 localhost pluto[4122]: |             b=C=US, ST=Rhode Island, O=MyCorp CA, OU=Software, CN=Work
Jun 15 11:09:13 localhost pluto[4122]: |    results  matched
Jun 15 11:09:13 localhost pluto[4122]: | trusted_ca_nss: trustee A = '(empty)'
Jun 15 11:09:13 localhost pluto[4122]: | trusted_ca_nss: trustor B = '(empty)'
 */

        for (sra = &c->spd; hp == NULL && sra != NULL;
             sra = sra->spd_next)
        {
                hp = find_host_pair(&sra->this.host_addr,
                                    sra->this.host_port,
                                    &sra->that.host_addr,
                                    sra->that.host_port);

                DBG(DBG_CONTROLMORE, {
                        char s2[SUBNETTOT_BUF];
                        char d2[SUBNETTOT_BUF];

                        subnettot(&sra->this.client, 0, s2,
                                  sizeof(s2));
                        subnettot(&sra->that.client, 0, d2,
                                  sizeof(d2));

                        DBG_log("  checking hostpair %s -> %s is %s",
                                s2, d2,
                                hp == NULL ? "not found" : "found");
                });

                if (hp == NULL)
                        continue;

                struct connection *d;

                for (d = hp->connections; d != NULL; d = d->hp_next) {
                        int wildcards, pathlen; /* XXX */

                        if (d->policy & POLICY_GROUP)
                                continue;

                        /*
                         * ??? same_id && match_id seems redundant.
                         * if d->spd.this.id.kind == ID_NONE, both TRUE
                         * else if c->spd.this.id.kind == ID_NONE,
                         *     same_id treats it as a wildcard and match_id
                         *     does not.  Odd.
                         * else if kinds differ, match_id FALSE
                         * else if kind ID_DER_ASN1_DN, wildcards are forbidden by same_id
                         * else match_id just calls same_id.
                         * So: if wildcards are desired, just use match_id.
                         * If they are not, just use same_id
                         */
                        if (!(same_id(&c->spd.this.id,
                                      &d->spd.this.id) &&
                              match_id(&c->spd.that.id,
                                       &d->spd.that.id, &wildcards) &&
                              trusted_ca_nss(c->spd.that.ca,
                                         d->spd.that.ca, &pathlen)))
                                continue;

                        const struct spd_route *sr;

                       for (sr = &d->spd; sr != NULL; sr = sr->spd_next) {
                                int newfit = ikev2_evaluate_connection_fit(
                                        d, sr, role, tsi, tsr, tsi_n, tsr_n);

                                if (newfit > bestfit_n) {
                                        /* ..... OXR: better prefix, port, protocol fitness check */
                                } else {
                                        DBG(DBG_CONTROLMORE,
                                            DBG_log("prefix fitness rejected d %s",
                                                    d->name));
                                }
                        }
                }
        }


        /* b is now the best connection (if there is one!) */

        if (bsr == NULL) {
                /* ??? why do we act differently based on role?
                 * Paul: that's wrong. prob the idea was to not
                 * send a notify if we are message initiator
                 */
                if (role == ORIGINAL_INITIATOR)
                        return STF_FAIL;
                else
                        return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
        }

        /* ..... */
}

/* programs/pluto/ikev2_child.c */



/*
 * RFC 5996 section 2.9 "Traffic Selector Negotiation"
 * Future: section 2.19 "Requesting an Internal Address on a Remote Network"
 */
int ikev2_evaluate_connection_fit(const struct connection *d,
                                  const struct spd_route *sr,
                                  enum original_role role,
                                  const struct traffic_selector *tsi,
                                  const struct traffic_selector *tsr,
                                  int tsi_n,
                                  int tsr_n)
{
        int tsi_ni;
        int bestfit = -1;       /* OXR: means no fit at all */
        const struct end *ei, *er;

        if (role == ORIGINAL_INITIATOR) {
                ei = &sr->this;
                er = &sr->that;
        } else {
                ei = &sr->that;
                er = &sr->this;
        }

/*
 OXR: log snippet
Jun 15 11:09:13 localhost pluto[4122]: |   ikev2_evaluate_connection_fit evaluating our conn="home-work-cacert" I=0.0.0.0/32:0/0 R=192.168.1.5/32:0/0 (virt) to their:
Jun 15 11:09:13 localhost pluto[4122]: |     tsi[0]=192.168.1.226/192.168.1.226 proto=0 portrange 0-65535, tsr[0]=192.168.1.5/192.168.1.5 proto=0 portrange 0-65535
 */


        DBG(DBG_CONTROLMORE, {
                char ei3[SUBNETTOT_BUF];
                char er3[SUBNETTOT_BUF];
                subnettot(&ei->client,  0, ei3, sizeof(ei3));
                subnettot(&er->client,  0, er3, sizeof(er3));
                DBG_log("  ikev2_evaluate_connection_fit evaluating our "
                        "conn=\"%s\" I=%s:%d/%d R=%s:%d/%d %s to their:",
                        d->name, ei3, ei->protocol, ei->port,
                        er3, er->protocol, er->port,
                        is_virtual_connection(d) ? "(virt)" : "");
        });



        /* compare tsi/r array to this/that, evaluating how well it fits */
        for (tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
                int tsr_ni;

                for (tsr_ni = 0; tsr_ni < tsr_n; tsr_ni++) {
                        /* does it fit at all? */

                        DBG(DBG_CONTROLMORE, {
                                ipstr_buf bli;
                                ipstr_buf bhi;
                                ipstr_buf blr;
                                ipstr_buf bhr;
                                DBG_log("    tsi[%u]=%s/%s proto=%d portrange %d-%d, tsr[%u]=%s/%s proto=%d portrange %d-%d",
                                        tsi_ni,
                                        ipstr(&tsi[tsi_ni].low, &bli),
                                        ipstr(&tsi[tsi_ni].high, &bhi),
                                        tsi[tsi_ni].ipprotoid,
                                        tsi[tsi_ni].startport,
                                        tsi[tsi_ni].endport,
                                        tsr_ni,
                                        ipstr(&tsr[tsr_ni].low, &blr),
                                        ipstr(&tsr[tsr_ni].high, &bhr),
                                        tsr[tsr_ni].ipprotoid,
                                        tsr[tsr_ni].startport,
                                        tsr[tsr_ni].endport);
                        });
                        /* do addresses fit into the policy? */

                        /* 
                         * OXR: The initiator's &tsi[tsi_ni].low-high doesn't fit the connection's (ei->client) range:
                         * 192.168.1.226-192.168.1.226 doesn't fit 0.0.0.0/32
                         */

                       /*
                         * NOTE: Our parser/config only allows 1 CIDR, however IKEv2 ranges can be non-CIDR
                         *       for now we really support/limit ourselves to a single CIDR
                         */
                        if (addrinsubnet(&tsi[tsi_ni].low, &ei->client) &&
                            addrinsubnet(&tsi[tsi_ni].high, &ei->client) &&
                            addrinsubnet(&tsr[tsr_ni].low,  &er->client) &&
                            addrinsubnet(&tsr[tsr_ni].high, &er->client)) {
                                /*
                                 * now, how good a fit is it? --- sum of bits gives
                                 * how good a fit this is.
                                 */
                                int ts_range1 = ikev2_calc_iprangediff(
                                        tsi[tsi_ni].low, tsi[tsi_ni].high);
                                int maskbits1 = ei->client.maskbits;
                                int fitbits1 = maskbits1 + ts_range1;

                                int ts_range2 = ikev2_calc_iprangediff(
                                        tsr[tsr_ni].low, tsr[tsr_ni].high);
                                int maskbits2 = er->client.maskbits;
                                int fitbits2 = maskbits2 + ts_range2;

                                /* ??? this objective function is odd and arbitrary */
                                int fitbits = (fitbits1 << 8) + fitbits2;

                                /*
                                 * comparing for ports
                                 * for finding better local policy
                                 */
                                /* ??? arbitrary modification to objective function */
                                DBG(DBG_CONTROL,
                                    DBG_log("ei->port %d tsi[tsi_ni].startport %d  tsi[tsi_ni].endport %d",
                                            ei->port,
                                            tsi[tsi_ni].startport,
                                            tsi[tsi_ni].endport));
                                if (ei->port != 0 &&
                                    tsi[tsi_ni].startport == ei->port &&
                                    tsi[tsi_ni].endport == ei->port)
                                        fitbits = fitbits << 1;

                                if (er->port != 0 &&
                                    tsr[tsr_ni].startport == er->port &&
                                    tsr[tsr_ni].endport == er->port)
                                        fitbits = fitbits << 1;

                                DBG(DBG_CONTROLMORE,
                                            DBG_log("      has ts_range1=%u maskbits1=%u ts_range2=%u maskbits2=%u fitbits=%d <> %d",
                                                    ts_range1, maskbits1,
                                                    ts_range2, maskbits2,
                                                    fitbits, bestfit));

                                if (fitbits > bestfit)
                                        bestfit = fitbits;
                        }

        return bestfit;
} 
