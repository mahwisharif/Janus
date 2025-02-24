#ifndef _DSL_UTIL_
#define _DSL_UTIL_

#include "dr_api.h"
#include "janus.h"
#include "janus_api.h"


#define f.open(var)                 f.open(var, ios::in | ios::out)
#define get_return_val(I)           opnd_create_reg((reg_id_t)DR_REG_RAX)
#define get_arg1(I)                 opnd_create_reg((reg_id_t)DR_REG_RDI)
#define get_arg2(I)                 opnd_create_reg((reg_id_t)DR_REG_RSI)
#define get_arg3(I)                 opnd_create_reg((reg_id_t)DR_REG_RDX)
#define get_arg4(I)                 opnd_create_reg((reg_id_t)DR_REG_RCX)
#define get_arg5(I)                 opnd_create_reg((reg_id_t)DR_REG_R8)
#define get_arg6(I)                 opnd_create_reg((reg_id_t)DR_REG_R9)
#define get_value(opnd)             OPND_CREATE_INTPTR(get_value_exp(drcontext, bb, opnd, I))
#define get_addr(opnd)              get_addr_full(drcontext, bb,opnd, I) 
#define is_type(a,b)                OPND_CREATE_INT64(is_type_opnd(a,b))

void get_mem_rw_addr_full(void *dr_context, instrlist_t *bb, instr_t * instr);
#define get_mem_rw_addr(I)          get_mem_rw_addr_full(drcontext, bb, trigger)

app_pc get_nextaddr_full(void *dr_context, instr_t *instr);
#define get_nextaddr(I)             OPND_CREATE_INTPTR(get_nextaddr_full(drcontext, trigger))

opnd_t get_target_addr_indcall(instr_t * instr);
uintptr_t get_target_addr_call(instr_t * instr);
#define get_target_addr(I)          (instr_is_return(trigger)? OPND_CREATE_MEMPTR(DR_REG_XSP,0) : (instr_is_call_direct(trigger)? OPND_CREATE_INTPTR(get_target_addr_call(trigger)) : get_target_addr_indcall(trigger))) 

opnd_t get_src1(instr_t *instr);
opnd_t get_src2(instr_t *instr);
opnd_t get_dest(instr_t *instr);
bool mem_to_reg(instr_t *instr, opnd_t opnd);

void print(uint64_t x);
void print(uint32_t x);
void print(int x);
void print(char* x);
opnd_t get_mem_opnd(instr_t *instr);
uint64_t get_value_exp(void *dr_context, instrlist_t *bb, opnd_t opnd, instr_t * instr);
uint64_t get_addr_exp(void *dr_context, instrlist_t *bb, opnd_t opnd, instr_t * instr);
void get_addr_full(void *dr_context, instrlist_t *bb, opnd_t opnd, instr_t * instr);
uint64_t get_size(opnd_t opnd);
uint64_t is_type_opnd(opnd_t opnd, int type);
extern uint64_t vars[20];
extern uint64_t var_count;
#endif
