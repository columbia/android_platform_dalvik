HANDLE_OPCODE(OP_RETURN_WIDE /*vAA*/)
    vsrc1 = INST_AA(inst);
    AI_LOGE_W_METHOD("[AI] [return] v%d [return-wide]", vsrc1)
    ILOGV("|return-wide v%d", vsrc1);
    retval.j = GET_REGISTER_WIDE(vsrc1);
/* ifdef WITH_TAINT_TRACKING */
    SET_RETURN_TAINT(GET_REGISTER_TAINT_WIDE(vsrc1));
/* endif */
    GOTO_returnFromMethod();
OP_END
