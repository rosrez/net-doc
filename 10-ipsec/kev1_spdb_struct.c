/* programs/pluto/ikev1_spdb_struct.c */

notification_t parse_ipsec_sa_body(pb_stream *sa_pbs,           /* body of input SA Payload */
                                   const struct isakmp_sa *sa,  /* header of input SA Payload */
                                   pb_stream *r_sa_pbs,         /* if non-NULL, where to emit body of winning SA */
                                   bool selection,              /* if this SA is a selection, only one transform may appear */
                                   struct state *st)            /* current state object */
{
        /* ... */

       /* for each conjunction of proposals... */
        while (next_full) {

                /* ... */

                bool
                        ah_seen = FALSE,
                        esp_seen = FALSE,
                        ipcomp_seen = FALSE;

                /* ... */

                /* for each proposal in the conjunction */
                do {

                } 
     witch (next_proposal.isap_protoid) {
                        case PROTO_IPSEC_AH:
                                if (ah_seen) {
                                        loglog(RC_LOG_SERIOUS,
                                               "IPsec SA contains two simultaneous AH Proposals");
                                        return BAD_PROPOSAL_SYNTAX;
                                }
                                ah_seen = TRUE;
                                ah_prop_pbs = next_proposal_pbs;
                                ah_proposal = next_proposal;
                                ah_spi = next_spi;
                                break;

                        case PROTO_IPSEC_ESP:
                                if (esp_seen) {
                                        loglog(RC_LOG_SERIOUS,
                                               "IPsec SA contains two simultaneous ESP Proposals");
                                        return BAD_PROPOSAL_SYNTAX;
                                }
                                esp_seen = TRUE;
                                esp_prop_pbs = next_proposal_pbs;
                                esp_proposal = next_proposal;
                                esp_spi = next_spi;
                                break;

                        case PROTO_IPCOMP:
                                if (ipcomp_seen) {
                                        loglog(RC_LOG_SERIOUS,
                                               "IPsec SA contains two simultaneous IPCOMP Proposals");
                                        return BAD_PROPOSAL_SYNTAX;
                                }
                                ipcomp_seen = TRUE;
                                ipcomp_prop_pbs = next_proposal_pbs;
                                ipcomp_proposal = next_proposal;
                                ipcomp_cpi = next_spi;
                                break;
                        default:
                                loglog(RC_LOG_SERIOUS,
                                       "unexpected Protocol ID (%s) in IPsec Proposal",
                                       enum_show(&ikev1_protocol_names,
                                                 next_proposal.isap_protoid));
                                return INVALID_PROTOCOL_ID;

                        }
                } while (next_proposal.isap_proposal == propno);

                /* ... */

                if (esp_seen) {
                        /* ... */
                }

                /* ... */

                if (ipcomp_seen) {
                }

               /* save decoded version of winning SA in state */

                st->st_ah.present = ah_seen;
                if (ah_seen) {
                        st->st_ah.attrs = ah_attrs;
                        st->st_ah.our_lastused = mononow();
                        st->st_ah.peer_lastused = mononow();
                }

                st->st_esp.present = esp_seen;
                if (esp_seen) {
                        st->st_esp.attrs = esp_attrs;
                        st->st_esp.our_lastused = mononow();
                        st->st_esp.peer_lastused = mononow();
                }

                st->st_ipcomp.present = ipcomp_seen;
                if (ipcomp_seen) {
                        st->st_ipcomp.attrs = ipcomp_attrs;
                        st->st_ipcomp.our_lastused = mononow();
                        st->st_ipcomp.peer_lastused = mononow();
                }

                return NOTHING_WRONG;
        }

}
