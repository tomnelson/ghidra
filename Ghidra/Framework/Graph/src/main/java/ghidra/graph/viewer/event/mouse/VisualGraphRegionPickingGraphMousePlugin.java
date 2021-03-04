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
package ghidra.graph.viewer.event.mouse;

import docking.DockingUtils;
import ghidra.graph.viewer.GraphViewer;
import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualGraphViewUpdater;
import ghidra.graph.viewer.VisualVertex;
import org.jgrapht.Graph;
import org.jungrapht.visualization.MultiLayerTransformer;
import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.control.GraphElementAccessor;
import org.jungrapht.visualization.control.RegionSelectingGraphMousePlugin;
import org.jungrapht.visualization.control.SelectingGraphMousePlugin;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.selection.MutableSelectedState;
import org.jungrapht.visualization.selection.SelectedState;

import java.awt.Cursor;
import java.awt.Rectangle;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.Collection;

public class VisualGraphRegionPickingGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends RegionSelectingGraphMousePlugin<V, E> implements VisualGraphMousePlugin<V, E> {

// ALERT: -this class was created because mouseDragged() has a bug that generates a NPE
//        -also, mousePressed() has a bug in that it does not check the modifiers when the method is entered

	public VisualGraphRegionPickingGraphMousePlugin() {
//		super(InputEvent.BUTTON1_DOWN_MASK,
//			InputEvent.BUTTON1_DOWN_MASK | DockingUtils.CONTROL_KEY_MODIFIER_MASK);
	}

//	@Override
//	public boolean checkModifiers(MouseEvent e) {
//		if (e.getModifiersEx() == regionSelectionMask ||
//				e.getModifiersEx() == addRegionSelectionMask) {
//			return true;
//		}
//		return e.getModifiersEx() == regionSelectionMask;
//	}

//	@Override
//	public void mousePressed(MouseEvent e) {
//		if (!checkModifiers(e)) {
//			return;
//		}
//		super.mousePressed(e);
//	}

//	@Override
//	public void mouseDragged(MouseEvent e) {
//		if (locked) {
//			return;
//		}
//
//		GraphViewer<V, E> viewer = getGraphViewer(e);
//		if (vertex != null) {
//			dragVertices(e, viewer);
//		}
//		else {
//			increaseDragRectangle(e);
//		}
//
//		viewer.repaint();
//	}

//	private void increaseDragRectangle(MouseEvent e) {
//		Point2D out = e.getPoint();
//		int theModifiers = e.getModifiersEx();
//		if (theModifiers == addToSelectionModifiers || theModifiers == modifiers) {
//			if (down != null) {
//				((Rectangle)viewRectangle).setFrameFromDiagonal(down, out);
//			}
//		}
//	}

//	private void dragVertices(MouseEvent e, GraphViewer<V, E> viewer) {
//
//		java.awt.Point p = e.getPoint();
//		RenderContext<V, E> context = viewer.getRenderContext();
//		MultiLayerTransformer xformer = context.getMultiLayerTransformer();
//		Point2D layoutPoint = xformer.inverseTransform(p);
//		Point2D layoutDown = xformer.inverseTransform(down);
//		LayoutModel<V> layout = viewer.getVisualizationModel().getLayoutModel();
//		double dx = layoutPoint.getX() - layoutDown.getX();
//		double dy = layoutPoint.getY() - layoutDown.getY();
//		SelectedState<V> ps = viewer.getSelectedVertexState();
//
//		for (V v : ps.getSelected()) {
//			Point vertexPoint = layout.apply(v);
//			vertexPoint = vertexPoint.add(0, dy);
////			vertexPoint.setLocation(vertexPoint.getX() + dx, vertexPoint.getY() + dy);
//			layout.set(v, vertexPoint);
//			updatedArticulatedEdges(viewer, v);
//		}
//
//		down = p;
//		e.consume();
//	}

	private void updatedArticulatedEdges(GraphViewer<V, E> viewer, V v) {

		LayoutModel<V> layout = viewer.getVisualizationModel().getLayoutModel();
		Graph<V, E> graph = layout.getGraph();

		Collection<E> edges = graph.edgesOf(v);
		VisualGraphViewUpdater<V, E> updater = getViewUpdater(viewer);
		updater.updateEdgeShapes(edges);
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		if (isOverVertex(e)) {
			installCursor(cursor, e);
			e.consume();
		}
	}

	private boolean isOverVertex(MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
		return (GraphViewerUtils.getVertexFromPointInViewSpace(viewer, e.getPoint()) != null);
	}

	@SuppressWarnings("unchecked")
	private void installCursor(Cursor newCursor, MouseEvent e) {
		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();
		viewer.setCursor(newCursor);
	}

	/* Pretty sure we don't need this now that we update the vertex locations directly.  This 
	   was old code that pre-existed the preferred method for updating vertex locations.   Once
	   all tests are passing, and selecting edges of previously dragged vertices still works, 
	   the delete this code.
	   
	private void updateVertexLocationToCompensateForDraggingWorkaround(double dx, double dy, V v) {
		Point2D original = v.getLocation();
		original.setLocation(original.getX() + dx, original.getY() + dy);
		v.setLocation(original);
	}
	*/

//	@Override
//	public void mouseReleased(MouseEvent e) {
//
//		// We overrode this method here to clear the picked state of edges and vertices if we
//		// ever get a released event when the user is clicking somewhere that is not an edge or
//		// vertex
//		if (!isDragging() && vertex == null && edge == null) {
//			maybeClearPickedState(e);
//		}
//		super.mouseReleased(e);
//	}

	private boolean isDragging() {
		Rectangle2D frame = viewRectangle.getBounds().getFrame();
		return frame.getHeight() > 0;
	}

	@SuppressWarnings("unchecked")
	private void maybeClearPickedState(MouseEvent event) {
		VisualizationViewer<V, E> vv = (VisualizationViewer<V, E>) event.getSource();
		MutableSelectedState<V> pickedVertexState = vv.getSelectedVertexState();
		MutableSelectedState<E> pickedEdgeState = vv.getSelectedEdgeState();
		if (pickedEdgeState == null || pickedVertexState == null) {
			return;
		}

		GraphElementAccessor<V, E> pickSupport = vv.getPickSupport();
		LayoutModel<V> layout = vv.getVisualizationModel().getLayoutModel();

		Point2D mousePoint = event.getPoint();
		V v = pickSupport.getVertex(layout, mousePoint.getX(), mousePoint.getY());
		if (v != null) {
			return;
		}

		E e = pickSupport.getEdge(layout, mousePoint.getX(), mousePoint.getY());
		if (e != null) {
			return;
		}

		pickedEdgeState.clear();
		pickedVertexState.clear();
	}
}
