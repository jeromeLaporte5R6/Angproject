import angr
import claripy
import struct
import sys
def main():
    BUF_LEN = 6
    binary_path = "./quotme"

    # Étape 1: Charger le binaire
    proj = angr.Project(binary_path)

    pend = 0x401223
    # Étape 2: Créer l'état initial
    flag = claripy.BVS('flag', 8*BUF_LEN)
    state = proj.factory.entry_state( args=["./quotme", flag], mode = "symbolic_approximating")
    # state = proj.factory.blank_state(addr = 0x401223, stdin = flag)

    # Étape 3: Définir les conditions d'arrêt
    addr_to_find = 0x401246
    other_add = 0x401259



    # Étape 6: Lancer l'analyse
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=addr_to_find)
    print(simgr)
    # print(simgr.active)
    if simgr.found:
        sol_state = simgr.found[0]
        res = sol_state.solver.eval(flag)
        print("input : ", res)
        print("constraints : ", sol_state.solver.constraints)
        print(sol_state.posix.dumps(sys.stdin.fileno()))
    else :
        print(simgr)
    # while(len(simgr.active) >= 1):
    #     print("---NEW STEP---")
    #     print(simgr.active)
    #     for state in simgr.active :
    #         print(state)
    #         try :
    #             block = proj.factory.block(state.addr)
    #             print(state.solver.eval(flag))
    #             block.pp()
    #         except :
    #             pass
    #     simgr.step()
    #     print("\n")


if __name__ == '__main__':
    main()

