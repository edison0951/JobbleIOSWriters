###Using Static Analysis And Clang To Find Heartbleed
###利用静态分析和Clang发现关键Bug

###Background背景
Friday night I sat down with a glass of Macallan 15 and decided to write a static checker that would find the Heartbleed bug. I decided that I would write it as an out-of-tree clang analyzer plugin and evaluate it on a few very small functions that had the spirit of the Heartbleed bug in them, and then finally on the vulnerable OpenSSL code-base itself.

上周5晚上，我坐在a glass of Macallan 15，决定写一个能发现关键(Heartbleed)Bug的静态检测器。它应该作为Clang分析器的外围插件，利用一些有关键Bug的函数来测试它，最后是在脆弱的OpenSSL代码库上实现的

The Clang project ships an analysis infrastructure with their compiler, it’s invoked via scan-build. It hooks whatever existing make system you have to interpose the clang analyzer into the build process and the analyzer is invoked with the same arguments as the compiler. This way, the analyzer can ‘visit’ every compilation unit in the program that compiles under clang. There are some limitations to clang analyzer that I’ll touch on in the discussion section.
This exercise added to my list of things that I can only do while drinking: I have the best success with first-order logic while drinking beer, and I have the best success with clang analyzer while drinking scotch.

该锵项目附带的编译器进行分析的基础设施，它通过扫描生成调用。它挂钩的任何现有制造系统，您必须夹着铛分析仪集成到构建过程，并分析仪调用使用相同的参数作为编译器。通过这种方式，分析仪可以“访问”中，根据铛编译程序的每个编译单元。有一些限制，以铛分析仪，我会触及在讨论部分。 
这个练习加入到我的事情，我只能这样做，而饮用列表：我有一阶逻辑一边喝啤酒最好的成功，我有铛分析领域最成功的一边喝威士忌。

###Strategy

One approach to identify Heartbleed statically was proposed by Coverity recently, which is to taint the return values of calls to ntohl and ntohs as input data. One problem with doing static analysis on a big state machine like OpenSSL is that your analysis either has to know the state machine to be able to track what values are attacker influenced across the whole program, or, they have to have some kind of annotation in the program that tells the analysis where there is a use of input data.
I like this observation because it is pretty actionable. You mark ntohl calls as producing tainted data, which is a heuristic, but a pretty good one because programmers probably won’t htonl their own data.
What our clang analyzer plugin should do is identify locations in the program where variables are written using ntohl, taint them, and then alert when those tainted values are used as the size parameter to memcpy. Except, that isn’t quite right, it could be the use is safe. We’ll also check the constraints of the tainted values at the location of the call: if the tainted value hasn’t been constrained in some way by the program logic, and it’s used as an argument to memcpy, alert on a bug. This could also miss some bugs, but I’m writing this over a 24h period with some Scotch, so increasing precision can come later.
提出了通过Coverity的一种方法以静态确定Heartbleed最近，这是玷污调用ntohl相似，并且还有ntohs作为输入数据的返回值。用做静态分析一个大的状态机一样的OpenSSL的一个问题是，你的分析要么必须知道状态机能够追踪什么值在整个程序攻击的影响，或者，他们必须有一些类型的注释中告诉分析那里有一个用输入数据的程序。
我喜欢这个观察，因为它是相当可行的。您标记ntohl相似的呼叫为生产污染数据，这是一个启发式的，但一个相当不错的，因为程序员可能不会htonl自己的数据。
我们什么铛分析仪插件应该做的是确定的地点在变量使用ntohl相似，写程序，玷污他们，然后当这些污染值作为size参数memcpy的提醒。只是，这是不完全正确，也可能是使用是安全的。我们也将检查被感染的值的约束在调用的位置：如果有漏值尚未制约以某种方式通过程序逻辑，并使用它作为参数传递给memcpy的，警觉的一个bug 。这也可能错过了一些错误，但我在写这在一个24小时内用透明，从而增加精度可以晚一点。

###Clang analyzer details

The clang analyzer implements a type of symbolic execution to analyze C/C++ programs. Plugging in to this framework as an analyzer requires bending your mind around the clang analyzer view of program state. This is where I consumed the most scotch.
The analyzer, under the hood, performs a symbolic/abstract exploration of program state. This exploration is flow and path sensitive, so it is different from traditional compiler data flow analysis. The analysis maintains a “state” object for each path through the program, and in this state object are constraints and facts about the program’s execution on that path. This state object can be queried by your analyzer, and, your analyzer can change the state to include information produced by your analysis.
This was one of my biggest hurdles when writing the analyzer – once I have a “symbolic variable” in a particular state, how do I query the range of that symbolic variable? Say there is a program fragment that looks like this:
int data = ntohl(pkt_data);
if(data >= 0 && data < sizeof(global_arr)) {
 // CASE A
...
} else {
 // CASE B
 ...
}
When looking at this program from the analyzers point of view, the state “splits” at the if into two different states A and B. In state A, there is a constraint that data is between certain bounds, and in case B there is a constraint that data is NOT within certain bounds. How do you access this information from your checker?
If your checker calls the “dump” method on its given “state” object, data like the following will be printed out:
Ranges of symbol values:

 conj_$2{int} : { [-2147483648, -2], [0, 2147483647] }
 conj_$9{uint32_t} : { [0, 6] }
 
In this example, conj_$9{uint32_t} is our ‘data’ value above and the state is in the A state. We have a range on ‘data’ that places it between 0 and 6. How can we, as the checker, observe that there’s a difference between this range and an unconstrained range of say [-2147483648, 2147483648]?
The answer is, we create a formula that tests the symbolic value of ‘data’ against some conditions that we enforce, and then we ask the state what program states exist when this formula is true and when it is false. If a new formula contradicts an existing formula, the state is infeasible and no state is generated. So we create a formula that says, roughly, “data > 500″ to ask if data could ever be greater than 500. When we ask the state for new states where this is true and where it is false, it will only give us a state where it is false.
This is the kind of idiom used inside of clang analyzer to answer questions about constraints on state. The arrays bounds checkers use this trick to identify states where the sizes of an array are not used as constraints on indexes into the array.

###Implementation

Your analyzer is implemented as a C++ class. You define different “check” functions that you want to be notified of when the analyzer is exploring program state. For example, if your analyzer wants to consider the arguments to a function call before the function is called, you create a member method with a signature that looks like this:
void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
Your analyzer can then match on the function about to be (symbolically) invoked. So our implementation works in three stages:
Identify calls to ntohl/ntoh
Taint the return value of those calls
Identify unconstrained uses of tainted data
We accomplish the first and second with a checkPostCall visitor that roughly does this:

	void NetworkTaintChecker::checkPostCall(const CallEvent &Call,
		CheckerContext &C) const {
  			const IdentifierInfo *ID = Call.getCalleeIdentifier();

  			if(ID == NULL) {
    			return;
 		 }
 		 
 		 if(ID->getName() == "ntohl" || ID->getName() == "ntohs") {
    			ProgramStateRef State = C.getState();
    			SymbolRef         Sym = Call.getReturnValue().getAsSymbol();

    		if(Sym) {
      			ProgramStateRef newState = State->addTaint(Sym);
      			C.addTransition(newState);
    		}
  	}
  	
Pretty straightforward, we just get the return value, if present, taint it, and add the state with the tainted return value as an output of our visit via ‘addTransition’.
For the third goal, we have a checkPreCall visitor that considers a function call parameters like so:

	void NetworkTaintChecker::checkPreCall(const CallEvent &Call,
		CheckerContext &C) const {
  			ProgramStateRef State = C.getState();
  			const IdentifierInfo *ID = Call.getCalleeIdentifier();

  			if(ID == NULL) {
    				return;
  			}
  			if(ID->getName() == "memcpy") {
    				SVal            SizeArg = Call.getArgSVal(2);
    				ProgramStateRef state =C.getState();

    				if(state->isTainted(SizeArg)) {
      					SValBuilder       &svalBuilder = C.getSValBuilder();
      					Optional<NonLoc>  SizeArgNL = SizeArg.getAs<NonLoc>();

      					if(this->isArgUnConstrained(SizeArgNL, svalBuilder, state) == true) {
       					ExplodedNode  *loc = C.generateSink();
        					if(loc) {
          						BugReport *bug = new BugReport(*this->BT, "Tainted,
								unconstrained value used in memcpy size", loc);
          						C.emitReport(bug);
        					}
      					}
    				}
  			}
  	
Also relatively straightforward, our logic to check if a value is unconstrained is hidden in ‘isArgUnConstrained’, so if a tainted, symbolic value has insufficient constraints on it in our current path, we report a bug.

###Some implementation pitfalls

It turns out that OpenSSL doesn’t use ntohs/ntohl, they have n2s / n2l macros that re-implement the byte-swapping logic. If this was in LLVM IR, it would be tractable to write a “byte-swapping recognizer” that uses an amount of logic to prove when a piece of code approximates the semantics of a byte-swap.

There is also some behavior that I have not figured out in clang’s creation of the AST for openssl where calls to ntohs are replaced with __builtin_pre(__x), which has no IdentifierInfo and thus no name. To work around this, I replaced the n2s macro with a function call to xyzzy, resulting in linking failures, and adapted my function check from above to check for a function named xyzzy. This worked well enough to identify the Heartbleed bug.
Solution output with demo programs and OpenSSL
First let’s look at some little toy programs. Here is one toy example with output:
$ cat demo2.c

	...

	int data_array[] = { 0, 18, 21, 95, 43, 32, 51};

	int main(int argc, char *argv[]) {
  		int   fd;
  		char  buf[512] = {0};

  		fd = open("dtin", O_RDONLY);

  		if(fd != -1) {
    			int size;
    			int res;

   			res = read(fd, &size, sizeof(int));

    		if(res == sizeof(int)) {
      			size = ntohl(size);

      			if(size < sizeof(data_array)) {
        			memcpy(buf, data_array, size);
      			}

      			memcpy(buf, data_array, size);
    		}

    		close(fd);
  		}

  		return 0;
	}

$ ../docheck.sh
scan-build: Using '/usr/bin/clang' for static analysis
/usr/bin/ccc-analyzer -o demo2 demo2.c
demo2.c:30:7: warning: Tainted, unconstrained value used in memcpy size
      memcpy(buf, data_array, size);
      ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1 warning generated.
scan-build: 1 bugs found.
scan-build: Run 'scan-view /tmp/scan-build-2014-04-26-223755-8651-1' to
examine bug reports.
And finally, to see it catching Heartbleed in both locations it was present in OpenSSL, see the following:
Image
Image

###Discussion

The approach needs some improvement, we reason about if a tainted value is “appropriately” constrained or not in a very coarse-grained way. Sometimes that’s the best you can do though – if your analysis doesn’t know how large a particular buffer is, perhaps it’s enough to show to an analyst “hey, this value could be larger than 5000 and it is used as a parameter to memcpy, is that okay?”
I really don’t like the limitation in clang analyzer of operating on ASTs. I spent a lot of time fighting with the clang AST representation of ntohs and I still don’t understand what the source of the problem was. I kind of just want to consider a programs semantics in a virtual machine with very simple semantics, so LLVM IR seems ideal to me. This might just be my PL roots showing though.
I really do like the clang analyzers interface to path constraints. I think that interface is pretty powerful and once you get your head around how to apply your problem to asking states if new states satisfying your constraints are feasible, it’s pretty straightforward to write new analyses.
该方法需要一些改进，我们推理，如果一个污染值是“适当的”限制或无法在非常粗粒度的方式。有时候，这是最好的，你可以做，但 - 如果你的分析不知道多大的特定缓冲区，或许这足以展现给分析师“哎，这个值可能会大于5000 ，它是用来作为参数传递给memcpy的是，好吗？ “
我真的不喜欢限制在AST的经营铛分析仪。我花了很多时间还有ntohs的铛AST表示战斗，我还是不明白这个问题的来源。那种我只是想考虑在虚拟机中的程序语义具有非常简单的语义，所以LLVM IR似乎理想的给我。这可能只是我的根特等虽然表现。
我真的很喜欢的铛分析仪接口路径约束。我认为接口是相当强大的，一旦你得到你的头围绕如何对您的问题适用于要求各国是否有新的状态满足你的约束是可行的，这是很简单的写新的分析。

###Edit: Code Post

I’ve posted the code for the checker to Github, here.
我已经将代码放到了Github上，这里可以[下载](https://github.com/awruef/find-heartbleed)。