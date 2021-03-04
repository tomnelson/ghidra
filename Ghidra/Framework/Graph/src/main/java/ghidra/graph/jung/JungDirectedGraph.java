/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.graph.jung;

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DirectedPseudograph;

import java.util.Collection;

public class JungDirectedGraph<V, E extends GEdge<V>> extends DirectedPseudograph<V, E>
		implements GDirectedGraph<V, E> {

	public JungDirectedGraph() {
		super(null, null, false);
	}

	@Override
	public void addEdge(E e) {
		super.addEdge(e.getStart(), e.getEnd(), e);
	}

	@Override
	public void removeVertices(Iterable<V> toRemove) {
		toRemove.forEach(v -> super.removeVertex(v));
	}

	@Override
	public void removeEdges(Iterable<E> toRemove) {
		toRemove.forEach(e -> super.removeEdge(e));
	}

	@Override
	public E findEdge(V start, V end) {
		return getEdge(start, end);
	}

	@Override
	public Collection<V> getVertices() {
		return vertexSet();
	}

	@Override
	public Collection<E> getEdges() {
		return edgeSet();
	}

	@Override
	public boolean containsEdge(V from, V to) {
		return findEdge(from, to) != null;
	}

	@Override
	public GDirectedGraph<V, E> emptyCopy() {
		JungDirectedGraph<V, E> newGraph = new JungDirectedGraph<>();
		return newGraph;
	}

	@Override
	public GDirectedGraph<V, E> copy() {
		JungDirectedGraph<V, E> newGraph = new JungDirectedGraph<>();

		for (V v : vertexSet()) {
			newGraph.addVertex(v);
		}

		for (E e : edgeSet()) {
			newGraph.addEdge(e);
		}

		return newGraph;
	}

	@Override
	public boolean isEmpty() {
		return getVertexCount() == 0;
	}

	@Override
	public int getVertexCount() {
		return vertexSet().size();
	}

	@Override
	public int getEdgeCount() {
		return edgeSet().size();
	}

	@Override
	public Collection<E> getInEdges(V v) {
		return incomingEdgesOf(v);
	}

	@Override
	public Collection<E> getOutEdges(V v) {
		return outgoingEdgesOf(v);
	}
}
