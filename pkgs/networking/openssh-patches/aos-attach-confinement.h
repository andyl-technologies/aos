/* Fixed Linux post-auth confinement; see aos-attach-confinement.c. */
#ifndef AOS_ATTACH_CONFINEMENT_H
#define AOS_ATTACH_CONFINEMENT_H

void aos_attach_confinement_before_drop(void);
void aos_attach_confinement_after_drop(void);

#endif
