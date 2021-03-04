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

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.util.Msg;
import org.jgrapht.Graph;
import org.jgrapht.Graphs;
import org.jungrapht.visualization.layout.algorithms.util.Pair;

/**
 * A class that turns a {@link Graph} into a {@link GDirectedGraph}.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class JungToGDirectedGraphAdapter<V, E extends GEdge<V>> implements GDirectedGraph<V, E> {

	private Graph<V, E> delegate;

	public JungToGDirectedGraphAdapter(Graph<V, E> delegate) {
		this.delegate = delegate;
	}

	@Override
	public void addEdge(E e) {
		delegate.addEdge(e.getStart(), e.getEnd(), e);
	}

	@Override
	public boolean containsEdge(V from, V to) {
		return findEdge(from, to) != null;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public GDirectedGraph<V, E> emptyCopy() {

		if (delegate instanceof GDirectedGraph) {
			return ((GDirectedGraph) delegate).emptyCopy();
		}

		Class<? extends Graph> clazz = delegate.getClass();

		try {
			Constructor<? extends Graph> constructor = clazz.getConstructor((Class<?>[]) null);
			Graph newGraph = constructor.newInstance((Object[]) null);
			return new JungToGDirectedGraphAdapter(newGraph);
		}
		catch (Exception e) {
			// shouldn't happen
			Msg.showError(this, null, "Error Creating Graph",
				"Unable to create a new instance of graph: " + clazz, e);
			return null;
		}
	}

	@Override
	public GDirectedGraph<V, E> copy() {

		JungToGDirectedGraphAdapter<V, E> newGraph =
			(JungToGDirectedGraphAdapter<V, E>) emptyCopy();

		for (V v : delegate.vertexSet()) {
			newGraph.addVertex(v);
		}

		for (E e : delegate.edgeSet()) {
			newGraph.delegate.addEdge(e.getStart(), e.getEnd(), e);
		}

		return newGraph;
	}

	@Override
	public boolean isEmpty() {
		return getVertexCount() == 0;
	}

	@Override
	public Collection<E> getEdges() {
		return delegate.edgeSet();
	}

	@Override
	public Collection<E> getInEdges(V vertex) {
		return delegate.incomingEdgesOf(vertex);
	}

	@Override
	public Collection<V> getVertices() {
		return delegate.vertexSet();
	}

	@Override
	public Collection<E> getOutEdges(V vertex) {
		return delegate.outgoingEdgesOf(vertex);
	}

	@Override
	public boolean containsVertex(V vertex) {
		return delegate.containsVertex(vertex);
	}

	@Override
	public Collection<V> getPredecessors(V vertex) {
		return Graphs.predecessorListOf(delegate, vertex);
	}

	@Override
	public boolean containsEdge(E edge) {
		return delegate.containsEdge(edge);
	}

	@Override
	public int getEdgeCount() {
		return delegate.edgeSet().size();
	}

	@Override
	public Collection<V> getSuccessors(V vertex) {
		return Graphs.successorListOf(delegate, vertex);
	}

	@Override
	public int getVertexCount() {
		return delegate.vertexSet().size();
	}

	public Collection<V> getNeighbors(V vertex) {
		return Graphs.neighborListOf(delegate, vertex);
	}

	public int inDegree(V vertex) {
		return delegate.inDegreeOf(vertex);
	}

	@Override
	public Collection<E> getIncidentEdges(V vertex) {
		return delegate.edgesOf(vertex);
	}

	public int outDegree(V vertex) {
		return delegate.outDegreeOf(vertex);
	}

	public Collection<V> getIncidentVertices(E edge) {
		return Arrays.asList(delegate.getEdgeSource(edge), delegate.getEdgeTarget(edge));
	}

	public boolean isPredecessor(V v1, V v2) {
		return Graphs.predecessorListOf(delegate,v1).contains(v2);
//				delegate.isPredecessor(v1, v2);
	}

	public boolean isSuccessor(V v1, V v2) {
		return Graphs.successorListOf(delegate, v1).contains(v2);
	}

	@Override
	public E findEdge(V v1, V v2) {
		return delegate.getEdge(v1, v2);
	}

	public int getPredecessorCount(V vertex) {
		return getPredecessors(vertex).size();
	}

	public int getSuccessorCount(V vertex) {
		return getSuccessors(vertex).size();
	}

	public V getSource(E directed_edge) {
		return delegate.getEdgeSource(directed_edge);
	}

	public Collection<E> findEdgeSet(V v1, V v2) {
		return delegate.getAllEdges(v1, v2);
	}

	public V getDest(E directed_edge) {
		return delegate.getEdgeTarget(directed_edge);
	}

	public boolean isSource(V vertex, E edge) {
		return delegate.getEdgeSource(edge).equals(vertex);
//				delegate.isSource(vertex, edge);
	}

	@Override
	public boolean addVertex(V vertex) {
		return delegate.addVertex(vertex);
	}

	public boolean isDest(V vertex, E edge) {
		return delegate.getEdgeTarget(edge).equals(vertex);
	}

	public boolean addEdge(E edge, Collection<? extends V> vertices) {
		if (vertices.size() < 2) {
			return false;
		}
		List<V> vertexList = new ArrayList(vertices);
		return delegate.addEdge(vertexList.get(0), vertexList.get(1), edge);
	}

	public boolean addEdge(E e, V v1, V v2) {
		return delegate.addEdge(v1, v2, e);
	}

//	public boolean addEdge(E edge, Collection<? extends V> vertices, EdgeType edge_type) {
//		return delegate.addEdge(edge, vertices, edge_type);
//	}

//	public boolean addEdge(E e, V v1, V v2, EdgeType edgeType) {
//		return delegate.addEdge(e, v1, v2, edgeType);
//	}
//
//	@Override
	public boolean removeVertex(V vertex) {
		return delegate.removeVertex(vertex);
	}

	@Override
	public void removeVertices(Iterable<V> vertices) {
		vertices.forEach(v -> removeVertex(v));
	}

	@Override
	public void removeEdges(Iterable<E> edges) {
		edges.forEach(e -> removeEdge(e));
	}

	public Pair<V> getEndpoints(E edge) {
		return Pair.of(delegate.getEdgeSource(edge), delegate.getEdgeTarget(edge));
	}

	public V getOpposite(V vertex, E edge) {
		Pair<V> endpoints = getEndpoints(edge);
		if (endpoints.first.equals(vertex)) {
			return endpoints.second;
		}
		if (endpoints.second.equals(vertex)) {
			return endpoints.first;
		}
		return null;
	}

	@Override
	public boolean removeEdge(E edge) {
		return delegate.removeEdge(edge);
	}

	public boolean isNeighbor(V v1, V v2) {
		return getNeighbors(v1).contains(v2);
//		return delegate.isNeighbor(v1, v2);
	}

	public boolean isIncident(V vertex, E edge) {
		return getIncidentVertices(edge).contains(vertex);
//		return delegate.isIncident(vertex, edge);
	}

	public int degree(V vertex) {
		return delegate.degreeOf(vertex);
	}

	public int getNeighborCount(V vertex) {
		return getNeighbors(vertex).size();
	}

	public int getIncidentCount(E edge) {

		return 2;
	}

//	public EdgeType getEdgeType(E edge) {
//		return delegate.getEdgeType(edge);
//	}

//	public EdgeType getDefaultEdgeType() {
//		return delegate.getDefaultEdgeType();
//	}

//	public Collection<E> getEdges(EdgeType edge_type) {
//		return delegate.getEdges(edge_type);
//	}

//	public int getEdgeCount(EdgeType edge_type) {
//		return delegate.getEdgeCount(edge_type);
//	}

}
