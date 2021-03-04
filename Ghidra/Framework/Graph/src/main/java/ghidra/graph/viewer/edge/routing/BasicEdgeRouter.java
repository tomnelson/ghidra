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
package ghidra.graph.viewer.edge.routing;

import static ghidra.graph.viewer.GraphViewerUtils.getVertexBoundsInGraphSpace;

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;
import java.util.*;

import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import org.jgrapht.Graph;
import org.jungrapht.visualization.VisualizationServer;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;

public class BasicEdgeRouter<V extends VisualVertex, E extends VisualEdge<V>> {

	protected VisualizationServer<V, E> viewer;
	protected Collection<E> edges = null;

	public BasicEdgeRouter(VisualizationServer<V, E> viewer, Collection<E> edges) {
		this.viewer = viewer;
		this.edges = edges;
	}

	public void route() {
		for (E edge : edges) {
			List<Point> articulations = edge.getArticulationPoints();

			if (articulations.isEmpty()) {
				continue; // nothing to do
			}

			articulations = removeBadlyAngledArticulations(edge, articulations);
			edge.setArticulationPoints(articulations);

// TODO: not sure if we want to test for occlusion here too			
//			Shape edgeShape = getEdgeShapeInGraphSpace(viewer, edge);
//			if (!isOccluded(edge, edgeShape)) {
//
//			}
		}
	}

	protected boolean isOccluded(E edge, Shape graphSpaceShape) {

		LayoutModel<V> layout = viewer.getVisualizationModel().getLayoutModel();
		Graph<V, E> graph = layout.getGraph();
		Collection<V> vertices = graph.vertexSet();

		for (V vertex : vertices) {
			Rectangle vertexBounds = getVertexBoundsInGraphSpace(viewer, vertex);

			if (vertex == graph.getEdgeSource(edge) || vertex == graph.getEdgeTarget(edge)) {
				// do we ever care if an edge is occluded by its own vertices?
				continue;
			}

			if (graphSpaceShape.intersects(vertexBounds)) {
				return true;
			}
		}

		return false;
	}

	protected List<Point> removeBadlyAngledArticulations(E edge, List<Point> articulations) {

		LayoutModel<V> layout = viewer.getVisualizationModel().getLayoutModel();
		Graph<V, E> graph = layout.getGraph();
		V start = graph.getEdgeSource(edge);
		V end = graph.getEdgeTarget(edge);

		Point startPoint = layout.apply(start);
		Point endPoint = layout.apply(end);

		if (startPoint.y > endPoint.y) {
			// swap the top and bottom points, as our source vertex is below the destination
			Point newStart = endPoint;
			endPoint = startPoint;
			startPoint = newStart;
		}

		List<Point> newList = new ArrayList<>();
		for (Point articulation : articulations) {
			double deltaY = articulation.y - startPoint.y;
			double deltaX = articulation.x - startPoint.x;
			double theta = Math.atan2(deltaY, deltaX);
			double degrees = theta * 180 / Math.PI;

			if (degrees < 0 || degrees > 180) {
				continue;
			}

			deltaY = endPoint.y - articulation.y;
			deltaX = endPoint.x - articulation.x;
			theta = Math.atan2(deltaY, deltaX);
			degrees = theta * 180 / Math.PI;

			if (degrees < 0 || degrees > 180) {
				continue;
			}

			newList.add(articulation);
		}

		return newList;
	}
}
