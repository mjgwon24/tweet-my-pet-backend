package tweet_my_pet.tweet_my_pet_backend.service;

import org.locationtech.jts.geom.GeometryFactory;
import org.locationtech.jts.geom.Point;
import org.locationtech.jts.geom.Coordinate;
import org.springframework.stereotype.Service;

@Service
public class StoreService {

    private final GeometryFactory geometryFactory = new GeometryFactory();

    public Point createPoint(double latitude, double longitude) {
        return geometryFactory.createPoint(new Coordinate(longitude, latitude));
    }
}

