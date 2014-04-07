HANDLE_OPCODE(OP_MOVE_RESULT_WIDE /*vAA*/)
    vdst = INST_AA(inst);
    AI_LOGE_W_METHOD("[AI] [move-result-wide] v%d (0x%08llx)", vdst, retval.j)
    ILOGV("|move-result-wide v%d %s(0x%08llx)", vdst, kSpacing, retval.j);
    SET_REGISTER_WIDE(vdst, retval.j);
/* ifdef WITH_TAINT_TRACKING */
    SET_REGISTER_TAINT_WIDE(vdst, GET_RETURN_TAINT());
/* endif */
    FINISH(1);
OP_END
