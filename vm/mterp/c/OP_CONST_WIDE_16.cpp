HANDLE_OPCODE(OP_CONST_WIDE_16 /*vAA, #+BBBB*/)
    vdst = INST_AA(inst);
    vsrc1 = FETCH(1);
    AI_LOGE_W_METHOD("[AI] [assign] (= v%d %d) [const-wide/16]", vdst, (s2)vsrc1)
    ILOGV("|const-wide/16 v%d,#0x%04x", vdst, (s2)vsrc1);
    SET_REGISTER_WIDE(vdst, (s2)vsrc1);
/* ifdef WITH_TAINT_TRACKING */
    SET_REGISTER_TAINT_WIDE(vdst, TAINT_CLEAR);
/* endif */
    FINISH(2);
OP_END
