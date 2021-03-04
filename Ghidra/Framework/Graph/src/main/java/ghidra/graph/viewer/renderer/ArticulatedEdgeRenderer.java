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
package ghidra.graph.viewer.renderer;

import java.awt.Shape;
import java.awt.geom.GeneralPath;
import java.awt.geom.Point2D;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;

import ghidra.graph.viewer.*;
import ghidra.graph.viewer.edge.VisualEdgeRenderer;
import ghidra.graph.viewer.shape.ArticulatedEdgeTransformer;
import org.jgrapht.Graph;
import org.jungrapht.visualization.MultiLayerTransformer;
import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.util.PointUtils;

import static org.jungrapht.visualization.MultiLayerTransformer.*;

public class ArticulatedEdgeRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualEdgeRenderer<V, E> {

	@SuppressWarnings("unchecked")
	@Override
	public Shape getEdgeShape(RenderContext<V, E> rc, Graph<V, E> graph, E e, float x1, float y1,
							  float x2, float y2, boolean isLoop, Shape vertexShape) {

		if (isLoop) {
			return GraphViewerUtils.createEgdeLoopInGraphSpace(vertexShape, x1, y1);
		}

		GeneralPath path = new GeneralPath();
		path.moveTo(x1, y1);

		int offset = 0;
		BiFunction<Graph<V,E>,E, Shape> edgeShapeTransformer = rc.getEdgeShapeFunction();
		if (edgeShapeTransformer instanceof ArticulatedEdgeTransformer) {
			offset = ((ArticulatedEdgeTransformer<V, E>) edgeShapeTransformer).getOverlapOffset(e);
		}

		List<Point> articulations = e.getArticulationPoints();
		offset = updateOffsetForLeftOrRightHandSizeEdge(rc, offset, x1, articulations);
		for (Point point : articulations) {
			Point2D offsetPoint =
				new Point2D.Float((float) point.x + offset, (float) point.y + offset);
			point =
					PointUtils.convert(rc.getMultiLayerTransformer().transform(Layer.LAYOUT, offsetPoint));
			path.lineTo((float) point.x, (float) point.y);
			path.moveTo((float) point.x, (float) point.y);
		}

		path.lineTo(x2, y2);
		path.moveTo(x2, y2);
		path.closePath();

		return path;
	}

	private int updateOffsetForLeftOrRightHandSizeEdge(RenderContext<V, E> rc, int offset, float x,
			List<Point> articulations) {

		int size = articulations.size();
		if (size == 0) {
			// no articulations or start to destination only, with no angles
			return offset;
		}

		Point start = articulations.get(0);
		start =
				PointUtils.convert(rc.getMultiLayerTransformer().transform(Layer.LAYOUT, PointUtils.convert(start)));
		double delta = x - start.x;
		if (delta == 0) {
			// don't move the edge when it is directly below the vertex (this prevents having 
			// a slightly skewed/misaligned edge) 
			return 0;
		}

		boolean isLeft = delta > 0;
		return isLeft ? -offset : offset;
	}
}
