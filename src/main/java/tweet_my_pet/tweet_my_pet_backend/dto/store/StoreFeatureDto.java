package tweet_my_pet.tweet_my_pet_backend.dto.store;

import lombok.Builder;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.PetSizeType;
import tweet_my_pet.tweet_my_pet_backend.entity.store.StoreFeature;

import java.util.List;

public class StoreFeatureDto {
    // 매장 특징 추가 요청
    @Builder
    public record AddStoreFeatureRequest(
            List<PetSizeType> acceptPetSizes,
            boolean isParking,
            boolean isDogPark,
            boolean isDogSwimmingPool,
            boolean isInternet,
            boolean isBarbecue
    ) {
        public StoreFeature toEntity() {
            return StoreFeature.builder()
                    .acceptPetSizes(this.acceptPetSizes)
                    .isParking(this.isParking)
                    .isDogPark(this.isDogPark)
                    .isDogSwimmingPool(this.isDogSwimmingPool)
                    .isInternet(this.isInternet)
                    .isBarbecue(this.isBarbecue)
                    .build();
        }
    }

    // 매장 특징 조회 응답
    @Builder
    public record FetchStoreFeatureResponse(
            Long id,
            List<PetSizeType> acceptPetSizes,
            boolean isParking,
            boolean isDogPark,
            boolean isDogSwimmingPool,
            boolean isInternet,
            boolean isBarbecue
    ) {}
}
