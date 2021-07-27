#include <cassert>
#include "func.h"
#include "util.h"
using namespace std;
/*--- Global Var Decl Start ---*/
uint64_t inst_count = 0;

/*--- Global Var Decl End ---*/


/*--- DSL Function Start ---*/
void func_1(){
    inst_count = inst_count + 1;
}

/*--- DSL Function Finish ---*/

void exit_routine(){
    /*--- Termination Start ---*/
    print(inst_count);

/*--- Termination End ---*/
}
void init_routine(){
    /*--- Init Start ---*/

/*--- Init End ---*/
}
