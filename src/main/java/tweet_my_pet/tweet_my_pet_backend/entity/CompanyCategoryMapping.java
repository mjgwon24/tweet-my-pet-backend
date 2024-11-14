package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "company_category_mapping", schema = "tweet_my_pet")
public class CompanyCategoryMapping {
    @EmbeddedId
    private CompanyCategoryMappingId companyCategoryMappingId;

    @MapsId("companyCategoryId")
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "company_category_id", nullable = false)
    private CompanyCategory companyCategory;

    @MapsId("companyId")
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "company_id", nullable = false)
    private Company company;

}