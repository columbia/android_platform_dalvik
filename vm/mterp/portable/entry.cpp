/*
 * Main interpreter loop.
 *
 * This was written with an ARM implementation in mind.
 */
void dvmInterpretPortable(Thread* self)
{
#if defined(EASY_GDB)
    StackSaveArea* debugSaveArea = SAVEAREA_FROM_FP(self->interpSave.curFrame);
#endif
    DvmDex* methodClassDex;     // curMethod->clazz->pDvmDex
    JValue retval;
#ifdef WITH_TAINT_TRACKING
    Taint rtaint;
#endif

    /* core state */
    const Method* curMethod;    // method we're interpreting
    const u2* pc;               // program counter
    u4* fp;                     // frame pointer
    u2 inst;                    // current instruction
    /* instruction decoding */
    u4 ref;                     // 16 or 32-bit quantity fetched directly
    u2 vsrc1, vsrc2, vdst;      // usually used for register indexes
    /* method call setup */
    const Method* methodToCall;
    bool methodCallRange;

    /* static computed goto table */
    DEFINE_GOTO_TABLE(handlerTable);

    /* copy state in */
    curMethod = self->interpSave.method;
    pc = self->interpSave.pc;
    fp = self->interpSave.curFrame;
    retval = self->interpSave.retval;   /* only need for kInterpEntryReturn? */

#ifdef WITH_TAINT_MEASURE
    //FIXME: This part is invoked for all all method calls from target application
    // I want to move this out to somewhere else e.g., Interp.cpp.
    char* env;
    env = getenv("AND_INSTRUMENT");

    #define APP_NAME_SZ 256
    char app_name[APP_NAME_SZ];
    app_name[0] = 'L';
    char* tmp = &app_name[1];

    int app_sz = 0;
    unsigned i;
    char line[APP_NAME_SZ];
    
    FILE *f = fopen("/data/local/tmp/instrumented", "r");
    if (f == NULL) {
	//fall to the normal
	if (env) {
	    for ( app_sz = 0 ; env[app_sz]!='\0' && app_sz < APP_NAME_SZ; app_sz++) {
		    if (env[app_sz] == '.') {
			    tmp[app_sz] = '/';
		    } else {
			    tmp[app_sz] = env[app_sz];
		    }
	    }
	    tmp[app_sz] = '\0';
       }
   } else {
	/* read the app from file */
	if (fgets(line, APP_NAME_SZ, f) != NULL) {
		for ( app_sz = 0 ; line[app_sz]!='\0' && line[app_sz] != '\n'
						&& app_sz < APP_NAME_SZ; app_sz++) {
		    if (line[app_sz] == '.') {
			    tmp[app_sz] = '/';
		    } else {
			    tmp[app_sz] = line[app_sz];
		    }
	    	}
        }
	fclose(f);
   }

#if 0
    if (env) {

      for ( app_sz = 0 ; env[app_sz]!='\0' && app_sz < APP_NAME_SZ; app_sz++) {
        if (env[app_sz] == '.') {
          tmp[app_sz] = '/';
        } else {
          tmp[app_sz] = env[app_sz];
        }
      }
      tmp[app_sz] = '\0';
    }
#endif
#endif

#ifdef WITH_TAINT_TRACKING
    rtaint = self->interpSave.rtaint;
#endif

    methodClassDex = curMethod->clazz->pDvmDex;

    LOGVV("threadid=%d: %s.%s pc=%#x fp=%p",
        self->threadId, curMethod->clazz->descriptor, curMethod->name,
        pc - curMethod->insns, fp);

    /*
     * Handle any ongoing profiling and prep for debugging.
     */
    if (self->interpBreak.ctl.subMode != 0) {
        TRACE_METHOD_ENTER(self, curMethod);
        self->debugIsMethodEntry = true;   // Always true on startup
    }
    /*
     * DEBUG: scramble this to ensure we're not relying on it.
     */
    methodToCall = (const Method*) -1;

#if 0
    if (self->debugIsMethodEntry) {
        ILOGD("|-- Now interpreting %s.%s", curMethod->clazz->descriptor,
                curMethod->name);
        DUMP_REGS(curMethod, self->interpSave.curFrame, false);
    }
#endif

    FINISH(0);                  /* fetch and execute first instruction */

/*--- start of opcodes ---*/
