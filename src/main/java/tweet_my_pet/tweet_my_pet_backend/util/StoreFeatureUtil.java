package tweet_my_pet.tweet_my_pet_backend.util;

import tweet_my_pet.tweet_my_pet_backend.entity.store.StoreFeature;

import java.util.ArrayList;
import java.util.List;

public class StoreFeatureUtil {
    // 매장 특징 목록 전용 문자열로 변환
    static public String storeFeatureListToString(StoreFeature storeFeature) {
        List<String> features = new ArrayList<>();

        if (storeFeature.getIsSmallDog() && storeFeature.getIsMediumDog() && storeFeature.getIsLargeDog()) features.add("모든견종 가능");
        else {
            if (storeFeature.getIsSmallDog()) features.add("소형견");
            if (storeFeature.getIsMediumDog()) features.add("중형견");
            if (storeFeature.getIsLargeDog()) features.add("대형견");
        }
        if (storeFeature.getIsParking()) features.add("주차장");
        if (storeFeature.getIsDogPark()) features.add("애견운동장");
        if (storeFeature.getIsDogSwimmingPool()) features.add("애견수영장");
        if (storeFeature.getIsInternet()) features.add("인터넷");
        if (storeFeature.getIsBarbecue()) features.add("바베큐");
        if (storeFeature.getIsFoodPacking()) features.add("포장 가능");
        if (storeFeature.getIsWaitingPlace()) features.add("대기 공간");
        if (storeFeature.getIsKidSeat()) features.add("유아 의자");

        return String.join("·", features.stream().limit(3).toList());
    }
}
