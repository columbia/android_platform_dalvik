HANDLE_OPCODE(OP_REM_FLOAT /*vAA, vBB, vCC*/)
    {
        u2 srcRegs;
        vdst = INST_AA(inst);
        srcRegs = FETCH(1);
        vsrc1 = srcRegs & 0xff;
        vsrc2 = srcRegs >> 8;
        ILOGV("|%s-float v%d,v%d,v%d", "mod", vdst, vsrc1, vsrc2);
        SET_REGISTER_FLOAT(vdst,
            fmodf(GET_REGISTER_FLOAT(vsrc1), GET_REGISTER_FLOAT(vsrc2)));
/* ifdef WITH_TAINT_TRACKING */
#ifdef WITH_TAINT_TRACKING
        SET_REGISTER_TAINT_FLOAT(vdst,
	    (GET_REGISTER_TAINT_FLOAT(vsrc1)|GET_REGISTER_TAINT_FLOAT(vsrc2)));
#endif /*WITH_TAINT_TRACKING*/
/* endif */
    }
    FINISH(2);
OP_END
