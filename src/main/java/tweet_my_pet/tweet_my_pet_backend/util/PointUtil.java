package tweet_my_pet.tweet_my_pet_backend.util;

import org.springframework.data.geo.Point;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;

public class PointUtil {
    // 현재 내 위치와 매장 위치 간 거리 계산
    static public double calculateDistanceSpacing(Point myPoint, Point storePoint) {
        double theta = myPoint.getX() - storePoint.getX();
        double dist = Math.sin(deg2rad(myPoint.getY())) * Math.sin(deg2rad(storePoint.getY())) + Math.cos(deg2rad(myPoint.getY())) * Math.cos(deg2rad(storePoint.getY())) * Math.cos(deg2rad(theta));
        dist = Math.acos(dist);
        dist = rad2deg(dist);
        dist = dist * 60 * 1.1515;
        dist = dist * 1.609344; // 단위 mile 에서 km 변환
        dist = Math.round(dist * 10) / 10.0;
        return dist;
    }

    private static double rad2deg(double x) {
        return (x * 180.0 / Math.PI);
    }

    private static double deg2rad(double y) {
        return (y * Math.PI / 180.0);
    }

    // 위도, 경도 데이터 직렬화 변환
    public static String serializePoint(double longitude, double latitude) {
        try {
            Point point = new Point(longitude, latitude);

            // 직렬화
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(point);
            oos.flush();
            oos.close();

            // 16진수 변환
            byte[] serializedData = bos.toByteArray();
            StringBuilder hexBuilder = new StringBuilder();
            for (byte b : serializedData) {
                hexBuilder.append(String.format("%02X", b & 0xFF));
            }

            return hexBuilder.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize Point object", e);
        }
    }
}