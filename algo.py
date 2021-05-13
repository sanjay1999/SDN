import networkx as nx
import math

G = nx.Graph()

G.add_nodes_from(['s1', 's2', 's3', 's4', 's5'])
G.add_edge('s1', 's2', delay=2, bw=7) 
G.add_edge('s1', 's3', delay=3, bw=10)
G.add_edge('s2', 's4', delay=1, bw=5) 
G.add_edge('s2', 's5', delay=3, bw=10) 
G.add_edge('s3', 's4', delay=2, bw=7) 
G.add_edge('s4', 's5', delay=1, bw=6)

# for u, v, a in G.edges(data=True):
#     print(f"{u} -> {v} : {a}")

# print(G.edges['s1', 's2']['delay'])

def get_delay(N, u, v, c, X):
    return N.edges[u, v]['delay']

def get_bw(N, u, v, c, X):
    return c / N.edges[u, v]['bw']

def get_new_delay(N, u, v, c, X):
    return math.ceil(X * N.edges[u, v]['delay'] / c)

def get_new_bw(N, u, v, c, X):
    return math.ceil(X * get_bw(N, u, v, c, X) / c)

def MCP_Heustric(N, s, t, W1, W2, C1, C2, X):
    d = {}
    p = {}
    V = N.nodes()
    for i in V:
        for j in range(0, C2 + 1):
            d[(i, j)] = 2**32 - 1
            p[(i, j)] = None
            if(i == s):
                d[(i, j)] = 0
    
    for i in range(0, len(V) - 1):
        for j in range(0, C2 + 1):
            for u, v, att in N.edges(data=True):
                nj = j + W2(N, u, v, C2, X)
                nW1 = W1(N, u, v, C1, X)
                if nj <= C2 and d[(v, nj)] > d[(u, j)] + nW1:
                    d[(v, nj)] = d[(u, j)] + nW1
                    p[(v, nj)] = u
    
    # for i in V:
    #     for j in range(0, C2 + 1):
    #         print(i, j, d[(i, j)], p[(i, j)])

    for i in range(0, C2 + 1):
        # print(i, d[(t, i)])
        if d[(t, i)] <= C1:
            pn = None
            done = False
            current_node = t
            path = []
            while not done:
                # print(path)
                # print(f"current_node = {current_node}")
                # print(current_node)
                if current_node == s:
                    path.append(current_node)
                    done = True
                    break
                for j in range(0, C2 + 1):
                    # print(f"parent({current_node}, {j}) = {p[(current_node, j)]}")
                    if p[(current_node, j)] != None:
                        path.append(current_node)
                        current_node = p[(current_node, j)]
                        break
            path = path[::-1]
            print(path)
            return path
    
    return False

MCP_Heustric(G, 's1', 's5', get_delay, get_new_bw, 5, 2, 2)
MCP_Heustric(G, 's1', 's5', get_delay, get_new_bw, 5, 2, 2)
MCP_Heustric(G, 's1', 's5', get_delay, get_new_bw, 5, 2, 2)
MCP_Heustric(G, 's1', 's5', get_delay, get_new_bw, 5, 2, 2)