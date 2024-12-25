package tweet_my_pet.tweet_my_pet_backend.dto.store;

import lombok.Builder;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.PetSizeType;
import tweet_my_pet.tweet_my_pet_backend.entity.store.StoreFeature;

import java.util.List;

public class StoreFeatureDto {
    // 매장 특징 추가 요청
    @Builder
    public record CreateStoreFeatureRequest(
            boolean isSmallDog,
            boolean isMediumDog,
            boolean isLargeDog,
            boolean isParking,
            boolean isDogPark,
            boolean isDogSwimmingPool,
            boolean isInternet,
            boolean isBarbecue,
            boolean isToiletDivision,
            boolean isFoodPacking,
            boolean isWaitingPlace,
            boolean isKidSeat
    ) {
        public StoreFeature toEntity() {
            return StoreFeature.builder()
                    .isSmallDog(this.isSmallDog)
                    .isMediumDog(this.isMediumDog)
                    .isLargeDog(this.isLargeDog)
                    .isParking(this.isParking)
                    .isDogPark(this.isDogPark)
                    .isDogSwimmingPool(this.isDogSwimmingPool)
                    .isInternet(this.isInternet)
                    .isBarbecue(this.isBarbecue)
                    .isToiletDivision(this.isToiletDivision)
                    .isFoodPacking(this.isFoodPacking)
                    .isWaitingPlace(this.isWaitingPlace)
                    .isKidSeat(this.isKidSeat)
                    .build();
        }
    }

    // 매장 특징 조회 응답
    @Builder
    public record FetchStoreFeatureResponse(
            Long id,
            boolean isSmallDog,
            boolean isMediumDog,
            boolean isLargeDog,
            boolean isParking,
            boolean isDogPark,
            boolean isDogSwimmingPool,
            boolean isInternet,
            boolean isBarbecue,
            boolean isToiletDivision,
            boolean isFoodPacking,
            boolean isWaitingPlace,
            boolean isKidSeat
    ) {}
}
