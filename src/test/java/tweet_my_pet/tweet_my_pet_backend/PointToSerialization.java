package tweet_my_pet.tweet_my_pet_backend;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;
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
                {35.83555542, 129.209822015},
                {35.88171015, 129.2233053},
                {35.84205615, 129.21541387},
                {35.83774591, 129.210509813},
                {35.8344924, 129.210917},
                {35.83493929,129.2119557},
                {35.83506066, 129.2122823},
                {35.86503614, 129.2121608},
                {35.85042095, 129.1972566},
                {35.84746306, 129.2154139},
                {35.83981799, 129.2062844},
                {35.8391495, 129.2086493},
                {35.83813967,129.2092462},
                {35.83542379, 129.2146599},
                {35.83515799, 129.2127081}
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