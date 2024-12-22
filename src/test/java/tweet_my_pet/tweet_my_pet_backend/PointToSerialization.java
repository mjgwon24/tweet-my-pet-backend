package tweet_my_pet.tweet_my_pet_backend;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.geo.Point;
import tweet_my_pet.tweet_my_pet_backend.util.PointUtil;

import java.util.Arrays;
import java.util.List;

@SpringBootTest
@Transactional
public class PointToSerialization {
    @Test
    @DisplayName("위도 경도 데이터 직렬화 변환")
    void pointToSerializationTest() {
        // given - 위도 경도 데이터
        // longitude: x, latitude: y
        double[][] points = {
            {37.7539, 128.9131},
            {37.8839, 128.9331},
            {37.9939, 128.9231}
        };

        // when - points 개수만큼 직렬화 변환
        List<String> serializedPoints = Arrays.stream(points)
            .map(point -> PointUtil.serializePoint(point[0], point[1]))
            .toList();

        // then
        System.out.println("========== 직렬화 변환 결과 ==========");
        serializedPoints.forEach(point -> {
            System.out.println("Serialized Point: '\\x" + point + "'");
        });
    }
}
