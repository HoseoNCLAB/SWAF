#ifndef SWAF_MPM_HS_H
#define SWAF_MPM_HS_H

#include "mpm_ctx.h"
#include "sig_id.h"
#include "prefilter.h"
#include "mpm_config.h"


void MpmHSRegister(void);

void MpmHSGlobalCleanup(void);

/* 유닛 테스트를 위한 함수 */
void SCHSRegisterTests(void);   

void SCHSInitCtx(MpmCtx *);
void SCHSInitThreadCtx(MpmCtx *, MpmThreadCtx *);
void SCHSDestroyCtx(MpmCtx *);
void SCHSDestroyThreadCtx(MpmCtx *, MpmThreadCtx *);
int SCHSAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, SigIntId, uint32_t);
int SCHSAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                     uint32_t, SigIntId, uint32_t);
int SCHSPreparePatterns(MpmConfig *mpm_conf, MpmCtx *mpm_ctx);
uint32_t SCHSSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                    PrefilterRuleStore *pmq, const uint8_t *buf, const uint32_t buflen);
void SCHSPrintInfo(MpmCtx *mpm_ctx);
void SCHSPrintSearchStats(MpmThreadCtx *mpm_thread_ctx);

#endif /* SWAF_MPM_HS_H */