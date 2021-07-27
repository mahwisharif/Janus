/* Note that this file is automatic generated */
#include "DSLGen.h"
#include "DSLGenUtil.h"

/*--- Global Var Decl Start ---*/

/*--- Global Var Decl End ---*/

using namespace std;
using namespace janus;

void ruleGenerationTemplate(JanusContext &jc) {
/*--- Static RuleGen Start ---*/
for (auto &func: jc.functions){
    for (auto &I: func.instrs){
        if( get_opcode(I) == Instruction::Load){
            insertCustomRule<Instruction>(1,I,1, false, 0);
        }
    }
}

/*--- Static RuleGen Finish ---*/

}

