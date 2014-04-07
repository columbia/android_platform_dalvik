HANDLE_OPCODE($opcode /*vAA, vBBBB*/)
    vdst = INST_AA(inst);
    vsrc1 = FETCH(1);
    AI_LOGE_W_METHOD("[AI] [assign] (= v%d v%d) [move%s/from16]", vdst, vsrc1, 
        (INST_INST(inst) == OP_MOVE_FROM16) ? "" : "-object")
    ILOGV("|move%s/from16 v%d,v%d %s(v%d=0x%08x)",
        (INST_INST(inst) == OP_MOVE_FROM16) ? "" : "-object", vdst, vsrc1,
        kSpacing, vdst, GET_REGISTER(vsrc1));
    SET_REGISTER(vdst, GET_REGISTER(vsrc1));
/* ifdef WITH_TAINT_TRACKING */
    SET_REGISTER_TAINT(vdst, GET_REGISTER_TAINT(vsrc1));
/* endif */
    FINISH(2);
OP_END
