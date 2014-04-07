HANDLE_OPCODE(OP_MOVE_WIDE_16 /*vAAAA, vBBBB*/)
    vdst = FETCH(1);
    vsrc1 = FETCH(2);
    if (vdst == vsrc1 + 1) {
        /* move-wide v2, v1 
        => (= v3, v2)
        => (= v2, v1)
        */
        AI_LOGE_W_METHOD("[AI] [assign] (= v%d v%d) [move-wide/16 1]", vdst + 1, vsrc1 + 1)
        AI_LOGE_W_METHOD("[AI] [assign] (= v%d v%d) [move-wide/16 0]", vdst, vsrc1)
    } else {
        AI_LOGE_W_METHOD("[AI] [assign] (= v%d v%d) [move-wide/16 0]", vdst, vsrc1)
        AI_LOGE_W_METHOD("[AI] [assign] (= v%d v%d) [move-wide/16 1]", vdst + 1, vsrc1 + 1)
    }
    ILOGV("|move-wide/16 v%d,v%d %s(v%d=0x%08llx)", vdst, vsrc1,
        kSpacing+8, vdst, GET_REGISTER_WIDE(vsrc1));
    SET_REGISTER_WIDE(vdst, GET_REGISTER_WIDE(vsrc1));
/* ifdef WITH_TAINT_TRACKING */
    SET_REGISTER_TAINT_WIDE(vdst, GET_REGISTER_TAINT_WIDE(vsrc1));
/* endif */
    FINISH(3);
OP_END
