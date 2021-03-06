%verify "executed"
    /* const-wide/high16 vAA, #+BBBB000000000000 */
    FETCH(r1, 1)                        @ r1<- 0000BBBB (zero-extended)
    mov     r3, rINST, lsr #8           @ r3<- AA
    mov     r0, #0                      @ r0<- 00000000
// begin WITH_TAINT_TRACKING
    mov     r2, r1, lsl #16             @ r1<- BBBB0000
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(2)               @ advance rPC, load rINST
// begin WITH_TAINT_TRACKING
    add     r9, rFP, r3, lsl #3         @ r3<- &fp[AA]
// end WITH_TAINT_TRACKING
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
// begin WITH_TAINT_TRACKING
    SET_TAINT_CLEAR(r1)
    SET_TAINT_CLEAR(r3)
    stmia   r9, {r0-r3}                 @ vAA<- r0/r1
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction

