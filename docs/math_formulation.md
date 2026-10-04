# RiskPath AI — Mathematical Formulation & Algorithm Details

## 1. Graph Topology & Edge Weights

Let $G = (V, E)$ be a directed multigraph where $V = V_{\text{asset}} \cup V_{\text{finding}}$. Each directed edge $e = (u, v, k) \in E$ has:
- **Cost** $c(e) \in [0, \infty)$: Effort, time, or complexity required for an attacker to traverse the transition.
- **Probability** $p(e) \in (0, 1]$: Likelihood of transition success given compromise of source node $u$.

---

## 2. Attack Path Feasibility $F(P)$

For an attack path $P = (e_1, e_2, \dots, e_k)$ from entry point $v_{\text{entry}}$ to crown jewel $v_{\text{crown}}$, path feasibility combines cumulative transition probability with total traversal cost:

$$F(P) = \left( \prod_{i=1}^{k} p(e_i) \right) \cdot \frac{1}{1 + \sum_{i=1}^{k} c(e_i)}$$

- **High Feasibility**: Multi-hop paths with high success probability and low traversal resistance.
- **Low Feasibility**: Complex paths requiring multiple low-probability exploits or expensive transitions.

---

## 3. Risk-Weighted Path Criticality (RWPC) Chokepoint Metric

Traditional graph centrality (e.g. betweenness) treats all paths equally regardless of attacker exploitability or crown jewel consequence.

**Risk-Weighted Path Criticality ($\operatorname{RWPC}$)** weights paths by their composite feasibility and target asset criticality:

$$\operatorname{RWPC}(v) = \frac{\sum_{P \in \mathcal{P}(v)} F(P) \cdot \operatorname{Crit}(\text{target}(P))}{\sum_{P \in \mathcal{P}} F(P) \cdot \operatorname{Crit}(\text{target}(P))}$$

where:
- $\mathcal{P}$ is the set of all discovered feasible entry-to-crown attack paths.
- $\mathcal{P}(v)$ is the subset of paths traversing node $v$.
- $\operatorname{Crit}(u) \in [1, 10]$ is the business asset criticality of the target crown jewel.
- $\operatorname{RWPC}(v) \in [0.0, 1.0]$ represents the percentage of total crown jewel exposure eliminated if node $v$ is secured.

---

## 4. Multi-Objective Blast Radius Pareto Frontier

Given a compromised asset $u_0 \in V_{\text{asset}}$, the blast radius algorithm discovers all downstream reachable assets within maximum depth $d_{\text{max}}$.

Because an attacker may favor either **cheapest cost** or **highest probability**, we compute the non-dominated Pareto frontier at each hop distance $d$:

$$\mathcal{F}_d(u_0) = \operatorname{ParetoMin}_{(C, -\Pi)} \{ (C(P), \Pi(P)) \mid \text{path } P \text{ from } u_0 \text{ of length } d \}$$

A path state $(C_1, \Pi_1)$ dominates $(C_2, \Pi_2)$ if:
$$C_1 \le C_2 \quad \text{and} \quad \Pi_1 \ge \Pi_2 \quad \text{with at least one strict inequality.}$$

---

## 5. Exact Combinatorial Budget Optimization

Given candidate remediation actions $A = \{a_1, a_2, \dots, a_m\}$ with costs $\operatorname{cost}(a_i)$ and total budget $B$:

$$\max_{A^* \subseteq A} \left( \Delta |\mathcal{P}(A^*)|, \; \Delta \sum_{P \in \mathcal{P}(A^*)} F(P) \right) \quad \text{s.t.} \quad \sum_{a \in A^*} \operatorname{cost}(a) \le B$$

### Computational Complexity & Guarantees:
- **Ceiling**: Capped at $|A| \le 12$.
- **State Space**: $2^{12} = 4,096$ possible subsets.
- **Guarantee**: Global mathematical optimality with zero approximation error in $< 200\text{ms}$.
- **Immutable Deep Clones**: Each candidate subset is evaluated on an isolated copy of the NetworkX graph, ensuring pure deterministic idempotency.
