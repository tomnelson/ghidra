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
package ghidra.graph.viewer.layout;

import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.graph.viewer.renderer.ArticulatedEdgeRenderer;
import ghidra.graph.viewer.shape.ArticulatedEdgeTransformer;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;
import org.jgrapht.Graph;
import org.jungrapht.visualization.layout.model.DefaultLayoutModel;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.renderers.AbstractEdgeRenderer;
import org.jungrapht.visualization.renderers.Renderer;

import java.awt.Dimension;
import java.awt.Shape;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * A wrapper that allows for existing Jung layouts to be used inside of the Visual Graph system. 
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
//@formatter:off
public class JungWrappingVisualGraphLayoutAdapter<V extends VisualVertex, 
                                                  E extends VisualEdge<V>>
	extends DefaultLayoutModel<V>
	implements VisualGraphLayout<V, E> {
//@formatter:on

	private ArticulatedEdgeTransformer<V, E> edgeShapeTransformer =new ArticulatedEdgeTransformer<>();
	private ArticulatedEdgeRenderer<V, E> edgeRenderer = new ArticulatedEdgeRenderer<>();

	private List<WeakReference<LayoutListener<V>>> listeners = new ArrayList<>();

	protected LayoutModel<V> delegate;

	public JungWrappingVisualGraphLayoutAdapter(LayoutModel<V> jungLayout) {
		super(LayoutModel.builder());

		this.delegate = jungLayout;
	}

//	@Override
//	public void initialize() {
//		delegate.initialize();
//	}

//	@Override
//	public void reset() {
//		delegate.reset();
//	}

	@Override
	public LayoutPositions<V, E> calculateLocations(VisualGraph<V, E> graph, TaskMonitor monitor) {

		Map<V, Point> vertexLocations = new HashMap<>();
		Collection<V> vertices = graph.getVertices();
		for (V v : vertices) {
			Point location = delegate.apply(v);
			vertexLocations.put(v, location);
		}

		Map<E, List<Point>> edgeErticulations = new HashMap<>();
		Collection<E> edges = graph.getEdges();
		for (E edge : edges) {
			List<Point> newArticulations = new ArrayList<>();
			edgeErticulations.put(edge, newArticulations);
		}

		return LayoutPositions.createNewPositions(vertexLocations, edgeErticulations);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public JungWrappingVisualGraphLayoutAdapter cloneLayout(VisualGraph<V, E> newGraph) {

		LayoutModel<V> newJungLayout = cloneJungLayout(newGraph);
		return new JungWrappingVisualGraphLayoutAdapter(newJungLayout);
	}

//	@Override
//	public void setLocation(V v, Point location, ChangeType changeType) {
//		delegate.set(v, location);
//	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected LayoutModel<V> cloneJungLayout(VisualGraph<V, E> newGraph) {

		Class<? extends LayoutModel> delegateClass = delegate.getClass();
		try {
			Constructor<? extends LayoutModel> constructor = delegateClass.getConstructor(Graph.class);
			LayoutModel layout = constructor.newInstance(newGraph);
			return layout;
		}
		catch (Exception e) {
			throw new RuntimeException("Unable to clone jung graph: " + delegate.getClass(), e);
		}
	}

	@Override
	public boolean usesEdgeArticulations() {
		return false;
	}

	@Override
	public void dispose() {
		listeners.clear();
	}

	@Override
	public LayoutModel<V> layoutModel() {
		return delegate;
	}

	@Override
	public Graph<V, E> getGraph() {
		return delegate.getGraph();
	}

//	@Override
	public Dimension getSize() {
		return new Dimension(delegate.getWidth(), delegate.getHeight());
	}

	@Override
	public boolean isLocked(V v) {
		return delegate.isLocked(v);
	}

	@Override
	public void lock(V v, boolean lock) {
		delegate.lock(v, lock);
	}

//	@Override
	public void setGraph(Graph<V, ?> graph) {
		delegate.setGraph(graph);
	}

//	@Override
	public void setInitializer(Function<V, Point> t) {
		delegate.setInitializer(t);
	}

//	@Override
	public void setSize(Dimension d) {
		delegate.setSize(d.width, d.height);
//		syncVertexLocationsToLayout();
	}

//	private void syncVertexLocationsToLayout() {
//		Graph<V, E> g = getGraph();
//		Collection<V> vertices = g.vertexSet();
//		for (V v : vertices) {
//			delegate.set(v, )
//			v.setLocation(apply(v));
//		}
//	}

	@Override
	public Point apply(V v) {
		return delegate.apply(v);
	}

//==================================================================================================
// Default Edge Stuff
//==================================================================================================	
	@Override
	public AbstractEdgeRenderer<V, E> getEdgeRenderer() {
		return edgeRenderer;
	}

	//	@Override
	public BiFunction<Graph<V, E>, E, Shape> getEdgeShapeTransformer() {
		return edgeShapeTransformer;
	}

	@Override
	public Renderer.EdgeLabel<V, E> getEdgeLabelRenderer() {
		return null;
	}

//==================================================================================================
// Listener Stuff
//==================================================================================================

	@Override
	@SuppressWarnings("unchecked")
	public void addLayoutListener(LayoutListener<V> listener) {
		Class<? extends LayoutListener<V>> listenerClass =
			(Class<? extends LayoutListener<V>>) listener.getClass();
		if (listenerClass.isAnonymousClass()) {
			throw new AssertException("Cannot add anonymous listeners to a weak collection!");
		}
		listeners.add(new WeakReference<>(listener));
	}

	@Override
	public void removeLayoutListener(LayoutListener<V> listener) {
		Iterator<WeakReference<LayoutListener<V>>> iterator = listeners.iterator();
		for (; iterator.hasNext();) {
			WeakReference<LayoutListener<V>> reference = iterator.next();
			LayoutListener<V> layoutListener = reference.get();
			if (layoutListener == null) {
				iterator.remove();
			}

			if (layoutListener == listener) {
				iterator.remove();
			}
		}
	}

	private void fireVertexLocationChanged(V vertex, Point point, ChangeType type) {
		Iterator<WeakReference<LayoutListener<V>>> iterator = listeners.iterator();
		for (; iterator.hasNext();) {
			WeakReference<LayoutListener<V>> reference = iterator.next();
			LayoutListener<V> layoutListener = reference.get();
			if (layoutListener == null) {
				iterator.remove();
				continue;
			}

			layoutListener.vertexLocationChanged(vertex, Point.of(point.x, point.y), type);
		}
	}

//	@Override
	public void setLocation(V v, Point location) {
		delegate.set(v, location);
		fireVertexLocationChanged(v, location, ChangeType.USER);
	}

//	@Override
	public void setLocation(V v, Point location, ChangeType changeType) {
		delegate.set(v, location);
		fireVertexLocationChanged(v, location, changeType);
	}

	@SuppressWarnings("unchecked")
	@Override
	public VisualGraph<V, E> getVisualGraph() {
		return (VisualGraph<V, E>) getGraph();
	}
}
