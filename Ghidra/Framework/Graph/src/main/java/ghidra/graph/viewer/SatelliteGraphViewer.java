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
package ghidra.graph.viewer;

import java.awt.Dimension;

import ghidra.graph.viewer.event.mouse.VisualGraphPluggableGraphMouse;
import ghidra.graph.viewer.event.mouse.VisualGraphSatelliteGraphMouse;
import ghidra.graph.viewer.renderer.VisualGraphRenderer;
import ghidra.graph.viewer.renderer.VisualVertexSatelliteRenderer;
import org.jungrapht.visualization.AbstractSatelliteVisualizationViewer;
import org.jungrapht.visualization.DefaultSatelliteVisualizationViewer;
import org.jungrapht.visualization.SatelliteVisualizationViewer;
import org.jungrapht.visualization.renderers.BiModalRenderer;
import org.jungrapht.visualization.renderers.Renderer;

/**
 * A graph viewer that shows a scaled, complete rendering of the graph with which it is 
 * associated.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class SatelliteGraphViewer<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractSatelliteVisualizationViewer<V, E> {

	protected GraphViewer<V, E> graphViewer;
	private boolean docked;

	public SatelliteGraphViewer(GraphViewer<V, E> master, Dimension preferredSize) {
		super(SatelliteVisualizationViewer.builder(master).viewSize(preferredSize));
		this.graphViewer = master;
		getRenderer().setRenderer(BiModalRenderer.HEAVYWEIGHT,
				new VisualGraphRenderer<>(getComponent(),null));

		setGraphMouse(new VisualGraphSatelliteGraphMouse<>());
	}

	/**
	 * Sets the docked state of this viewer.  An undocked satellite viewer will be in its 
	 * own window.
	 * 
	 * @param docked true if this viewer is docked; false if it is undocked
	 */
	public void setDocked(boolean docked) {
		this.docked = docked;
	}

	/**
	 * Returns true if this satellite viewer is docked
	 * 
	 * @return true if this satellite viewer is docked
	 */
	public boolean isDocked() {
		return docked;
	}

	/**
	 * Gets the renderer to use with this satellite viewer.
	 * 
	 * @return the renderer
	 */
	public Renderer.Vertex<V, E> getPreferredVertexRenderer() {
		return new VisualVertexSatelliteRenderer<>();
	}

	@SuppressWarnings("unchecked")
	@Override
	public VisualGraphPluggableGraphMouse<V, E> getGraphMouse() {
		return (VisualGraphPluggableGraphMouse<V, E>) super.getGraphMouse();
	}

	@Override
	public void setGraphMouse(GraphMouse graphMouse) {
		if (!(graphMouse instanceof VisualGraphPluggableGraphMouse)) {
			// our parent class will install a graph mouse that is not ours
			return;
		}
		super.setGraphMouse(graphMouse);
	}

}
