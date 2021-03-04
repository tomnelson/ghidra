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

import org.jungrapht.visualization.layout.model.Point;

import java.awt.geom.Point2D;

public class PointUtils {

    // convert from Point to Point2D

    public static Point2D convert(Point p) {
        return new Point2D.Double(p.x, p.y);
    }

    public static Point convert(Point2D p2d) {
        return Point.of(p2d.getX(), p2d.getY());
    }
}
