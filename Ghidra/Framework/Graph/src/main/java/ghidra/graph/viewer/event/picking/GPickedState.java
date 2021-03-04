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
package ghidra.graph.viewer.event.picking;

import java.awt.event.ItemListener;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import ghidra.graph.viewer.event.picking.PickListener.EventSource;
import org.jungrapht.visualization.selection.MultiMutableSelectedState;
import org.jungrapht.visualization.selection.MutableSelectedState;
import org.jungrapht.visualization.selection.SelectedState;

/**
 * This picked-state is a wrapper for {@link SelectedState} that allows us to broadcast events
 * with the trigger of that event.
 *
 * @param <V> the vertex type
 */
public class GPickedState<V> implements MutableSelectedState<V> {

	private Set<PickListener<V>> listeners = new CopyOnWriteArraySet<>();

	private final MultiMutableSelectedState<V> pickedStateDelegate;
	private EventSource pendingEventSource = null;

	public GPickedState(MultiMutableSelectedState<V> pickedState) {
		this.pickedStateDelegate = pickedState;
		pickedState.addItemListener(e -> {
			EventSource source =
				(pendingEventSource != null) ? pendingEventSource : EventSource.INTERNAL;
			@SuppressWarnings("rawtypes")
			MultiMutableSelectedState state = (MultiMutableSelectedState) e.getSource();
			Object[] selectedObjects = state.getSelectedObjects();
			notifyVerticesPicked(selectedObjects, source);
		});
	}

	private void notifyVerticesPicked(Object[] selectedVertices, EventSource source) {
		Set<V> vertices = getSet(selectedVertices);
		for (PickListener<V> listener : listeners) {
			listener.verticesPicked(vertices, source);
		}
	}

	// this better be OK; this is an API method that uses Object, but the vertices should be our type
	@SuppressWarnings("unchecked")
	private Set<V> getSet(Object[] vertices) {
		Set<V> set = new HashSet<>();
		for (Object vertice : vertices) {
			set.add((V) vertice);
		}
		return set;
	}

	public void addPickingListener(PickListener<V> pickListener) {
		listeners.add(pickListener);
	}

	public void removePickingListener(PickListener<V> pickListener) {
		listeners.remove(pickListener);
	}

	/**
	 * Picks the given vertex, but signals that the pick is really just to make sure that the 
	 * vertex is picked in order to match the graph's notion of the current location.  To pick a 
	 * vertex and signal that the location has changed, call {@link #select(Object, boolean)}.
	 * Calling this method is the same as calling 
	 * <pre>pickToSync(vertex, false);</pre>
	 * 
	 * @param vertex the vertex to pick
	 */
	public void pickToSync(V vertex) {
		pickToSync(vertex, false);
	}

	/**
	 * Picks the given vertex, but signals that the pick is really just to make sure that the 
	 * vertex is picked in order to match the graph's notion of the current location.  To pick a 
	 * vertex and signal that the location has changed, call {@link #select(Object, boolean)}
	 * 
	 * @param vertex the vertex to pick
	 * @param addToSelection true signals that the given vertex should be picked, but not to 
	 *                       remove any other picked vertices; false signals to pick the given
	 *                       vertex and to clear any other picked vertices
	 */
	public void pickToSync(V vertex, boolean addToSelection) {
		pendingEventSource = EventSource.EXTERNAL;
		if (!addToSelection) {
			pickedStateDelegate.clear();
		}
		pickedStateDelegate.select(vertex, true);
		pendingEventSource = null;
	}

	/**
	 * A convenience method to clear the current selected vertices and select the given vertex
	 * 
	 * @param vertex the vertex to pick
	 */
	public void pickToActivate(V vertex) {
		pendingEventSource = EventSource.INTERNAL;
		pickedStateDelegate.clear();
		pickedStateDelegate.select(vertex, true);
		pendingEventSource = null;
	}

	@Override
	public boolean select(V element) {
		return pickedStateDelegate.select(element);
	}

	// standard pick from toolkit
	@Override
	public boolean select(V vertex, boolean b) {
		pendingEventSource = EventSource.INTERNAL;
		boolean result = pickedStateDelegate.select(vertex, b);
		pendingEventSource = null;
		return result;
	}

	@Override
	public boolean deselect(V element) {
		return pickedStateDelegate.deselect(element);
	}

	@Override
	public boolean deselect(V element, boolean fireEvents) {
		return pickedStateDelegate.deselect(element, fireEvents);
	}

	@Override
	public boolean select(Collection<V> elements) {
		return pickedStateDelegate.select(elements);
	}

	@Override
	public boolean select(Collection<V> elements, boolean fireEvents) {
		return pickedStateDelegate.select(elements, fireEvents);
	}

	@Override
	public boolean deselect(Collection<V> elements) {
		return pickedStateDelegate.deselect(elements);
	}

	@Override
	public boolean deselect(Collection<V> elements, boolean fireEvents) {
		return pickedStateDelegate.deselect(elements, fireEvents);
	}

	@Override
	public void clear() {
		pendingEventSource = EventSource.INTERNAL;
		pickedStateDelegate.clear();
		pendingEventSource = null;
	}

	@Override
	public void clear(boolean fireEvents) {
		pickedStateDelegate.clear();
	}

	@Override
	public boolean isSelected(V v) {
		return pickedStateDelegate.isSelected(v);
	}

	@Override
	public Set<V> getSelected() {
		return pickedStateDelegate.getSelected();
	}

//	@Override
//	public boolean isPicked(V vertex) {
//		return pickedStateDelegate.isSelected(vertex);
//	}

	@Override
	public Object[] getSelectedObjects() {
		return pickedStateDelegate.getSelectedObjects();
	}

	@Override
	public void addItemListener(ItemListener l) {
		pickedStateDelegate.addItemListener(l);
	}

	@Override
	public void removeItemListener(ItemListener l) {
		pickedStateDelegate.removeItemListener(l);
	}
}
