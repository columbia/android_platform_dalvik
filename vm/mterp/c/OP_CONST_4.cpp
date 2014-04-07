HANDLE_OPCODE(OP_CONST_4 /*vA, #+B*/)
    {
        s4 tmp;

        vdst = INST_A(inst);
        tmp = (s4) (INST_B(inst) << 28) >> 28;  // sign extend 4-bit value
        AI_LOGE_W_METHOD("[AI] [assign] (= v%d %d) [const/4 444]", vdst, (s4) tmp)
        ILOGV("|const/4 v%d,#0x%02x", vdst, (s4)tmp);
        SET_REGISTER(vdst, tmp);
/* ifdef WITH_TAINT_TRACKING */
	SET_REGISTER_TAINT(vdst, TAINT_CLEAR);
/* endif */
    }
    FINISH(1);
OP_END
