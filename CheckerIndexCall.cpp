#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"

using namespace clang;
using namespace ento;

int loaded = 0;

typedef struct
{
	char name[0x20];     //函数名称
	int argloc;         //待检测的参数位置
	int type;        //类别
	int L;          //下限
	int R;           //上限
} FR;

typedef std::vector<FR> FRList;
FRList frl;

using namespace clang;
using namespace ento;

namespace {
class CheckerIndexCall : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;
  void initRules(CheckerContext &C) const;
public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

};
} // end anonymous namespace


void CheckerIndexCall::checkPostCall(const CallEvent &Call,
                                    CheckerContext &C) const {

  if (!Call.isGlobalCFunction()) {
    return;
  }
  initRules(C);
  const Expr *Callee = Call.getOriginExpr();
  const IdentifierInfo *II = Call.getCalleeIdentifier();
  const CallExpr *CE = dyn_cast<CallExpr>(Callee);
  
  if (!II) {
    return;
  }
  if (!CE) {
    return;
  }
  int i;
  
  for(i=0; i<frl.size(); i++)
  {
	  
	    FR si = frl.at(i);

	    if (II->isStr(si.name)) 
		{
			//std::cerr<<Call.getArgSVal(si.argloc).isConstant()<<std::endl;
			if(!Call.getArgSVal(si.argloc).isConstant())
			{
				std::string rep = "(Ignored) Arg " + std::to_string(si.argloc) + " of function \'" + si.name + "\' is non-constant.";
				ExplodedNode *N = C.generateNonFatalErrorNode(C.getState());
				if (!N)
					return;
				if(!BT)
					BT.reset(new BugType(this, rep, rep));
				auto report =
					std::make_unique<PathSensitiveBugReport>(*BT, BT->getDescription(), N);
				report->addRange(Callee->getSourceRange());
				C.emitReport(std::move(report));
				BT.release();
				return;
			}	

			const llvm::APSInt* arg1 = Call.getArgSVal(si.argloc).getAsInteger();
		  
			if(si.type == 1 && arg1->getExtValue() == 0)
			{
				std::string rep = "Arg " + std::to_string(si.argloc) + " of function \'" + si.name + "\' cannot be zero.";
				ExplodedNode *N = C.generateNonFatalErrorNode(C.getState());
				if (!N)
					return;
				if(!BT)
					BT.reset(new BugType(this, rep, rep));
				//BT = BugType(this, rep, rep);
				auto report =
					std::make_unique<PathSensitiveBugReport>(*BT, BT->getDescription(), N);
				report->addRange(Callee->getSourceRange());
				C.emitReport(std::move(report));
				BT.release();
				return;
			}
			
			if(si.type == 2  && (arg1->getExtValue() < si.L || arg1->getExtValue() > si.R))
			{
				std::string rep = "Arg " + std::to_string(si.argloc) + " of function \'" + si.name + "\' should be in range [" + std::to_string(si.L) + "," + std::to_string(si.R) + "].";
				ExplodedNode *N = C.generateNonFatalErrorNode(C.getState());
				if (!N)
					return;
				if(!BT)
					BT.reset(new BugType(this, rep, rep));
				//BT = BugType(this, rep, rep);
				auto report =
					std::make_unique<PathSensitiveBugReport>(*BT, BT->getDescription(), N);
				report->addRange(Callee->getSourceRange());
				C.emitReport(std::move(report));
				BT.release();
				return;
			}
			
		
		

	  }
  }
  

  
}

void CheckerIndexCall::initRules(CheckerContext &C) const {
	if(loaded)
		return;
	FILE * fp = fopen("/home/student-20191001815/config.csv","r");
	FR tmp;
	while(fscanf(fp,"%19s,%d,%d,%d,%d",tmp.name,&tmp.argloc,&tmp.type,&tmp.L,&tmp.R)!=0)
		frl.push_back(tmp);
	loaded = 1;
}


// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<CheckerIndexCall>(
      "plugin.CheckerIndexCall", "CheckerIndexCall",
      "");
}



extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
