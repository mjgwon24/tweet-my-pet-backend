package tweet_my_pet.tweet_my_pet_backend.util;

import tweet_my_pet.tweet_my_pet_backend.entity.store.StoreFeature;

import java.util.ArrayList;
import java.util.List;

public class StoreFeatureUtil {
    // 매장 특징 목록 전용 문자열로 변환
    static public String storeFeatureListToString(StoreFeature storeFeature) {
        List<String> features = new ArrayList<>();

        storeFeature.getAcceptPetSizes().forEach(petSize -> features.add(petSize.toString()));

        if (storeFeature.getIsParking()) features.add("주차장");
        if (storeFeature.getIsDogPark()) features.add("애견운동장");
        if (storeFeature.getIsDogSwimmingPool()) features.add("애견수영장");
        if (storeFeature.getIsInternet()) features.add("인터넷");
        if (storeFeature.getIsBarbecue()) features.add("바베큐");

        return String.join("·", features.stream().limit(3).toList());
    }
}
