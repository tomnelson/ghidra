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
package ghidra.graph.job;

import java.awt.geom.Point2D;
import java.util.*;
import java.util.Map.Entry;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import ghidra.graph.viewer.*;
import ghidra.graph.viewer.layout.LayoutPositions;
import org.jungrapht.visualization.layout.model.Point;

public class RelayoutFunctionGraphJob<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractGraphTransitionJob<V, E> {

	public RelayoutFunctionGraphJob(GraphViewer<V, E> viewer, boolean useAnimation) {
		super(viewer, useAnimation);
	}

	@Override
	protected Animator createAnimator() {

		initializeVertexLocations();
		clearLocationCache();

		if (!useAnimation) {
			return null;
		}

		updateOpacity(0);

		Animator newAnimator =
			PropertySetter.createAnimator(duration, this, "percentComplete", 0.0, 1.0);
		newAnimator.setAcceleration(0f);
		newAnimator.setDeceleration(0.8f);

		return newAnimator;
	}

	@Override
	protected void finished() {
		super.finished();

// TODO it is jarring to re-fit the graph if the user was zoomed in.  I'm torn on what the right
//		thing to do is
//		FunctionGraphView view = controller.getView();
//		FunctionGraphUtils.fitGraphToViewerNow(view.getPrimaryGraphViewer(), true);
	}

	@Override
	protected void initializeVertexLocations() {
		//
		// this may be the same as the current locations, or they may be updated, depending upon
		// user options
		// 

		LayoutPositions<V, E> futurePositions = calculateDefaultLayoutLocations();
		Map<V, Point> destinationLocations = futurePositions.getVertexLocations();
		finalEdgeArticulations = futurePositions.getEdgeArticulations();

		//
		// Create the new vertex locations.
		//
		Collection<V> vertices = graph.getVertices();
		for (V vertex : vertices) {
			Point currentPoint = toLocation(vertex);
			Point startPoint = currentPoint;
			Point vertexPoint = destinationLocations.get(vertex);
			Point destinationPoint = vertexPoint;
			TransitionPoints transitionPoints = new TransitionPoints(startPoint, destinationPoint);
			vertexLocations.put(vertex, transitionPoints);
		}

		//
		// We have to move edge articulations--create transition points.
		//
		Map<E, List<Point>> edgeArticulations = futurePositions.getEdgeArticulations();
		Set<Entry<E, List<Point>>> entrySet = edgeArticulations.entrySet();
		for (Entry<E, List<Point>> entry : entrySet) {
			E edge = entry.getKey();
			List<Point> currentArticulations = edge.getArticulationPoints();
			List<Point> newArticulations = entry.getValue();
			List<ArticulationTransitionPoints> transitionPoints = getArticulationTransitionPoints(
				currentArticulations, newArticulations, destinationLocations, edge);

			edgeArticulationLocations.put(edge, transitionPoints);
		}
	}

	private List<ArticulationTransitionPoints> getArticulationTransitionPoints(
			List<Point> currentArticulations, List<Point> newArticulations,
			Map<V, Point> destinationLocations, E edge) {

		if (currentArticulations.size() > newArticulations.size()) {
			return getArticulationTransitionPointsWhenStartingWithMorePoints(currentArticulations,
				newArticulations, destinationLocations, edge);
		}
		return getArticulationTransitionPointsWhenStartingWithLessPoints(currentArticulations,
			newArticulations, destinationLocations, edge);
	}

	private List<ArticulationTransitionPoints> getArticulationTransitionPointsWhenStartingWithLessPoints(
			List<Point> currentArticulations, List<Point> newArticulations,
			Map<V, Point> destinationLocations, E edge) {

		List<ArticulationTransitionPoints> transitionPoints = new ArrayList<>();

		// 
		// We will have to add articulations to the current edge now so that we can
		// animate their creation.
		//
		List<Point> newStartArticulationsPoints = new ArrayList<>();

		// default to start vertex so to handle the case where we started with no articulations
		Point lastValidStartPoint = toLocation(edge.getStart());
		for (int i = 0; i < newArticulations.size(); i++) {
			Point endPoint = newArticulations.get(i);

			Point startPoint =lastValidStartPoint;
			if (i < currentArticulations.size()) {
				// prefer the new articulations, while we have some
				startPoint = currentArticulations.get(i);
				lastValidStartPoint = startPoint;
			}

			transitionPoints.add(new ArticulationTransitionPoints(startPoint, endPoint));
			newStartArticulationsPoints.add(startPoint);
		}

		edge.setArticulationPoints(newStartArticulationsPoints);

		return transitionPoints;
	}

	private List<ArticulationTransitionPoints> getArticulationTransitionPointsWhenStartingWithMorePoints(
			List<Point> currentArticulations, List<Point> newArticulations,
			Map<V, Point> destinationLocations, E edge) {

		List<ArticulationTransitionPoints> transitionPoints = new ArrayList<>();

		for (int i = 0; i < currentArticulations.size(); i++) {

			Point startPoint = currentArticulations.get(i);
			Point endPoint = startPoint;
			if (i < newArticulations.size()) {
				// prefer the new articulations, while we have some
				endPoint = newArticulations.get(i);
			}

			transitionPoints.add(new ArticulationTransitionPoints(startPoint, endPoint));
		}

		return transitionPoints;
	}
}
