HANDLE_OPCODE($opcode /*vAA*/)
    vsrc1 = INST_AA(inst);
    if (!AI_IS_SYSTEM_LIB(methodToCall->clazz->descriptor)) {
        AI_LOGE_W_METHOD("[AI] [return] v%d [return%s]",
            vsrc1, (INST_INST(inst) == OP_RETURN) ? "" : "-object")
    }
    ILOGV("|return%s v%d",
        (INST_INST(inst) == OP_RETURN) ? "" : "-object", vsrc1);
    retval.i = GET_REGISTER(vsrc1);
/* ifdef WITH_TAINT_TRACKING */
    SET_RETURN_TAINT(GET_REGISTER_TAINT(vsrc1));
/* endif */
    GOTO_returnFromMethod();
OP_END
