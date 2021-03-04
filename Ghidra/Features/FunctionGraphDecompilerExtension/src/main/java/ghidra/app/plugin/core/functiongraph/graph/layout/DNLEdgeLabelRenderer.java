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
package ghidra.app.plugin.core.functiongraph.graph.layout;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.program.model.symbol.FlowType;
import org.jgrapht.Graph;
import org.jungrapht.visualization.MultiLayerTransformer;
import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.VisualizationModel;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.renderers.EdgeLabelRenderer;
import org.jungrapht.visualization.renderers.Renderer;
import org.jungrapht.visualization.transform.shape.GraphicsDecorator;

import static org.jungrapht.visualization.MultiLayerTransformer.*;

/**
 * An edge label renderer used with the {@link DecompilerNestedLayout}
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
class DNLEdgeLabelRenderer<V extends FGVertex, E extends FGEdge>
		implements Renderer.EdgeLabel<V, E> {

	private static final int DEFAULT_EDGE_OFFSET = 20;

	private VisualGraphVertexShapeTransformer<V> vertexShapeTransformer =
		new VisualGraphVertexShapeTransformer<>();

	private double edgeOffset;

	DNLEdgeLabelRenderer(double condenseFactor) {
		this.edgeOffset = DEFAULT_EDGE_OFFSET * (1 - condenseFactor);
	}

	@Override
	public void labelEdge(RenderContext<V, E> rc, LayoutModel<V> layoutModel, E e, String text) {

		Graph<V, E> jungGraph = layoutModel.getGraph();
		if (!rc.getEdgeIncludePredicate().test(e)) {
			return;
		}

		V startv = jungGraph.getEdgeSource(e);
		V endv = jungGraph.getEdgeTarget(e);

		Predicate<V> includeVertex = rc.getVertexIncludePredicate();
		if (!includeVertex.test(startv) ||
			!includeVertex.test(endv)) {
			return;
		}

		Point start = layoutModel.apply(startv);
		MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
		Point2D startPoint = multiLayerTransformer.transform(Layer.LAYOUT, start.x, start.y);
		start = Point.of(startPoint.getX(), startPoint.getY());

		Shape vertexShape = vertexShapeTransformer.apply(startv);
		Rectangle vertexBounds = vertexShape.getBounds();
		int xDisplacement = rc.getLabelOffset();

		Point2D labelPointOffset = new Point2D.Double();

		// note: location is centered
		double cx = start.x;
		double cy = start.y;

		EdgeLabelRenderer labelRenderer = rc.getEdgeLabelRenderer();
		Font font = rc.getEdgeFontFunction().apply(e);
		boolean isSelected = rc.getSelectedEdgeState().isSelected(e);
		Component component = labelRenderer.getEdgeLabelRendererComponent(rc.getScreenDevice(),
			text, font, isSelected, e);
		int labelWidth = component.getPreferredSize().width;

		List<Point> articulationPoints = e.getArticulationPoints();
		if (articulationPoints.isEmpty()) {
			double vertexBottom = start.y + (vertexBounds.height >> 1); // location is centered
			double textY = (int) (vertexBottom + edgeOffset); // below the vertex; above the bend 
			double textX = (int) (start.x + xDisplacement); // right of the edge
			labelPointOffset.setLocation(textX, textY);
		}
		else if (articulationPoints.size() == 1) {
			// articulation must have been removed
			return;
		}
		else {

			Point bend1 = articulationPoints.get(0);
			bend1 = PointUtils.convert(multiLayerTransformer.transform(Layer.LAYOUT, bend1.x, bend1.y));
			articulationPoints.set(0, bend1);
			Point bend2 = articulationPoints.get(1);
			bend2 = PointUtils.convert(multiLayerTransformer.transform(Layer.LAYOUT, bend2.x, bend2.y));
			articulationPoints.set(1, bend2);

			double vertexSide = cx + (vertexBounds.width >> 1);
			double vertexBottom = cy + (vertexBounds.height >> 1);

			double bx1 = bend1.x;

			FlowType flow = e.getFlowType();
			boolean isRight = flow.isFallthrough() || flow.isUnConditional();

			if (articulationPoints.size() == 2) {

				double textX = (int) (vertexSide + edgeOffset); // right of the vertex 
				double textY = (int) (cy + edgeOffset); // above the edge 
				labelPointOffset.setLocation(textX, textY);
			}
			else { // 3 or 4 articulations

				double textY = (int) (vertexBottom + edgeOffset); // below the vertex; above the bend 
				double textX = (int) (bx1 + xDisplacement); // right of the edge
				if (!isRight) {
					textX = bx1 - xDisplacement - labelWidth;
				}

				labelPointOffset.setLocation(textX, textY);
			}
		}

		Dimension d = component.getPreferredSize();

		GraphicsDecorator g = rc.getGraphicsContext();
		AffineTransform old = g.getTransform();
		AffineTransform xform = new AffineTransform(old);
		xform.translate(labelPointOffset.getX(), labelPointOffset.getY());

		g.setTransform(xform);
		g.draw(component, rc.getRendererPane(), 0, 0, d.width, d.height, true);
		g.setTransform(old);

		// debug
		//labelArticulations(component, g, rc, e);
	}

	@SuppressWarnings("unused") // used during debug
	private void labelArticulations(Component component, GraphicsDecorator g,
			RenderContext<V, E> rc, E e) {

		int offset = 5;
		int counter = 1;
		List<Point> points = e.getArticulationPoints();
		for (int i=0; i<points.size(); i++) {
//		for (Point p : points) {
			Point p = points.get(i);

			MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
			p = PointUtils.convert(multiLayerTransformer.transform(Layer.LAYOUT, p.x, p.y));
			points.set(i, p);

			EdgeLabelRenderer labelRenderer = rc.getEdgeLabelRenderer();
			Font font = rc.getEdgeFontFunction().apply(e);
			boolean isSelected = rc.getSelectedEdgeState().isSelected(e);
			component = labelRenderer.getEdgeLabelRendererComponent(rc.getScreenDevice(),
				"p" + counter++, font, isSelected, e);

			Dimension d = component.getPreferredSize();
			AffineTransform old = g.getTransform();
			AffineTransform xform = new AffineTransform(old);
			xform.translate(p.x + offset, p.y);
			g.setTransform(xform);
			g.draw(component, rc.getRendererPane(), 0, 0, d.width, d.height, true);
			g.setTransform(old);
		}
	}
}
