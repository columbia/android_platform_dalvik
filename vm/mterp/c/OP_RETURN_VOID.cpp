HANDLE_OPCODE(OP_RETURN_VOID /**/)
    AI_LOGE_W_METHOD("[AI] [return-void] %s [return-void]", "NO REGISTER")
    ILOGV("|return-void");
#ifndef NDEBUG
    retval.j = 0xababababULL;    // placate valgrind
#endif
/* ifdef WITH_TAINT_TRACKING */
    SET_RETURN_TAINT(TAINT_CLEAR);
/* endif */
    GOTO_returnFromMethod();
OP_END
